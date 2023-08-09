#include "sigscanner/sigscanner.hpp"
#include <chrono>

using namespace std::chrono_literals;

sigscanner::thread_pool::~thread_pool()
{
  this->destroy();
}

void sigscanner::thread_pool::create(std::size_t count)
{
  if (this->running)
  {
    return;
  }

  this->running = true;
  this->threads.reserve(count);
  for (std::size_t i = 0; i < count; i++)
  {
    this->threads.emplace_back(&sigscanner::thread_pool::thread_loop, this);
  }
}

void sigscanner::thread_pool::destroy(bool force)
{
  this->force_stop = force;
  this->running = false;
  std::this_thread::sleep_for(10ms);
  for (auto &thread: this->threads)
  {
    if (thread.joinable())
    {
      thread.join();
    }
  }
  this->threads.clear();
  this->tasks.clear();
  this->force_stop = false; // Setting here means we don't have to check running before locking in thread_loop
}

void sigscanner::thread_pool::add_task(std::function<void()> &&task)
{
  std::lock_guard<std::mutex> lock(this->tasks_mutex);
  this->tasks.emplace_back(std::move(task));
}

void sigscanner::thread_pool::thread_loop()
{
  std::unique_lock<std::mutex> lock(this->tasks_mutex, std::defer_lock);
  std::function<void()> task;
  while (true)
  {
    if (this->force_stop)
    {
      return;
    }
    {
      lock.lock();
      if (this->tasks.empty())
      {
        lock.unlock();
        if (!this->running)
        {
          return;
        }
        std::this_thread::yield();
        continue;
      }
      task = std::move(this->tasks.back());
      this->tasks.pop_back();
      lock.unlock();
    }
    task();
  }
}
