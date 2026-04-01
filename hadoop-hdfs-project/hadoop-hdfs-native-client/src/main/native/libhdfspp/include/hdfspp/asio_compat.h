/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Compatibility header for Boost.Asio API changes.
 *
 * Boost >= 1.87 removed deprecated io_service, resolver::query,
 * resolver::iterator, io_service::work, and io_service::post().
 * This header provides a compatibility layer so libhdfspp builds
 * with both old (>= 1.72) and new (>= 1.87) Boost versions.
 */
#ifndef INCLUDE_HDFSPP_ASIO_COMPAT_H_
#define INCLUDE_HDFSPP_ASIO_COMPAT_H_

#include <boost/version.hpp>

// Boost 1.87+ removed the deprecated io_service API and buffer types
#if BOOST_VERSION >= 108700

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/buffer.hpp>

// Provide compatibility aliases in boost::asio namespace
namespace boost { namespace asio {
  using mutable_buffers_1 = mutable_buffer;
  using const_buffers_1 = const_buffer;
}}

namespace hdfs {
namespace asio_compat {
  using io_service = boost::asio::io_context;
  using work_guard = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;

  inline work_guard make_work_guard(boost::asio::io_context &ctx) {
    return boost::asio::make_work_guard(ctx);
  }

  template <typename Func>
  inline void post(boost::asio::io_context &ctx, Func &&f) {
    boost::asio::post(ctx, std::forward<Func>(f));
  }

  using resolver_results = boost::asio::ip::tcp::resolver::results_type;
}
}

#else

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace hdfs {
namespace asio_compat {
  using io_service = boost::asio::io_service;

  // Wrap io_service::work to match work_guard interface
  class work_guard {
  public:
    explicit work_guard(boost::asio::io_service &svc) : work_(svc) {}
  private:
    boost::asio::io_service::work work_;
  };

  inline work_guard make_work_guard(boost::asio::io_service &svc) {
    return work_guard(svc);
  }

  template <typename Func>
  inline void post(boost::asio::io_service &svc, Func &&f) {
    svc.post(std::forward<Func>(f));
  }

  using resolver_results = boost::asio::ip::tcp::resolver::iterator;
}
}

#endif

#endif // include guard
