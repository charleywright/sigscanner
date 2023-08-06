#include "thread_pool.hpp"
#include <chrono>

using namespace std::chrono_literals;

thread_pool::~thread_pool()
{
  this->destroy();
}

void thread_pool::create(unsigned int count)
{
  if (count == 0)
  {
    count = std::thread::hardware_concurrency();
  }

  this->active = true;
  for (std::size_t i = 0; i < count; i++)
  {
    this->threads.emplace_back(&thread_pool::thread_loop, this);
  }
}

void thread_pool::destroy()
{
  this->active = false;
  std::this_thread::sleep_for(100ms);
  for (auto &thread: this->threads)
  {
    if (thread.joinable())
    {
      thread.join();
    }
  }
}

void thread_pool::add_task(std::function<void()> &&task)
{
  std::lock_guard<std::mutex> lock(this->tasks_mutex);
  this->tasks.emplace_back(std::move(task));
}

void thread_pool::thread_loop()
{
  std::unique_lock<std::mutex> lock(this->tasks_mutex, std::defer_lock);
  while (true)
  {
    std::function<void()> task;
    {
      lock.lock();
      if (this->tasks.empty())
      {
        lock.unlock();
        if (!this->active)
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
