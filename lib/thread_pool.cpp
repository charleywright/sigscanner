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
        /*
         * Benchmarked on a 5950X running Arch Linux with 30 threads
         * Method:            % spent in scan_file_internal
         * sleep_for(5ms)     50.73, 47.45, 51.21   = 49.77
         * sleep_for(4ms)     51.82, 47.34, 45.44   = 48.20
         * sleep_for(3ms)     50.67, 50.52, 52.35   = 51.18
         * sleep_for(2ms)     42.13, 40.33, 41.83   = 41.43
         * sleep_for(1ms)     34.55, 32.60, 37.44   = 34.86
         * sleep_for(0ms)     12.04, 13.21, 12.93   = 12.73
         * yield()            12.89, 12.89, 12.59   = 12.79
         * spinning           10.12, 11.68, 10.41   = 10.74
         *
         * This tells us somewhere between 2-5ms is the sweet spot (for this system).
         */
        std::this_thread::sleep_for(3ms);
        continue;
      }
      task = std::move(this->tasks.back());
      this->tasks.pop_back();
      lock.unlock();
    }
    task();
  }
}
