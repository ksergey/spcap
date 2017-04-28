#ifndef KSERGEY_queue_280417163916
#define KSERGEY_queue_280417163916

#include <vector>
#include <map>
#include <memory>
#include <spcap/spcap.hpp>

namespace examples {

/* Represent a PCAP file as queue */
class queue final
{
private:
    /* PCAP file reader */
    spcap::file file_;
    /* Last read packet */
    spcap::raw_packet front_;

public:
    queue(const queue&) = delete;
    queue& operator=(const queue&) = delete;

    /* Construct queue */
    explicit queue(const std::string& path)
        : file_(path)
    {
        /* (try)Read first packet */
        pop();
    }

    /* Return front packet */
    const spcap::raw_packet& front() const noexcept
    { return front_; }

    /* Pop front packet */
    void pop()
    { front_ = file_.next(); }

    /* Return true if queue empty */
    bool empty() const noexcept
    { return file_.eof(); }
};

/* Packet queue with priority by packet timestamp */
class priority_queue final
{
private:
    using queue_ptr = std::unique_ptr< queue >;
    /* Queues storage */
    std::vector< queue_ptr > storage_;
    /* Timetsamp priority map */
    std::map< std::uint64_t, queue* > priority_;

public:
    /* Construct priority queue */
    explicit priority_queue(std::size_t reserve_size = 96)
    { storage_.reserve(reserve_size); }

    /* Add PCAP to queue */
    void add_file(const std::string& path)
	{
		storage_.emplace_back(std::make_unique< queue >(path));
		auto* q = storage_.back().get();
		if (!q->empty()) {
			auto& p = q->front();
			priority_.emplace(p.timestamp(), q);
		}
	}

    /* Return front queue packet */
    const spcap::raw_packet& front() const noexcept
    { return priority_.begin()->second->front(); }

    /* Pop front packet from queue */
    void pop()
    {
        auto* q = priority_.begin()->second;
        priority_.erase(priority_.begin());
        q->pop();
        if (!q->empty()) {
            auto& packet = q->front();
            priority_.emplace(packet.timestamp(), q);
        }
    }

    /* Return true if queue empty */
    bool empty() const noexcept
    { return priority_.empty(); }
};

} /* namespace examples */

#endif /* KSERGEY_queue_280417163916 */
