#include <napi.h>
#include <sispopmq/connections.h>
#include <sispopmq/sispopmq.h>

namespace nsispopmq {

using namespace std::literals;

namespace {
    template <typename T, typename F>
    T napi_cast(const Napi::Env& env, F&& value) {
        return T::New(env, std::forward<F>(value));
    }
    template <typename T, typename F>
    T napi_cast(const Napi::CallbackInfo& info, F&& value) {
        return napi_cast<T>(info.Env(), std::forward<F>(value));
    }

    template <typename F>
    Napi::Buffer<uint8_t> napi_copy_bytes(const Napi::Env& env, const F& value) {
        static_assert(sizeof(*value.data()) == 1);
        return Napi::Buffer<uint8_t>::Copy(
                env, reinterpret_cast<const uint8_t*>(value.data()), value.size());
    }
}  // namespace

struct ctors {
    Napi::FunctionReference NConnectionID, NAddress, NMessage, NSispopMQ, NReply;
};

class NConnectionID : public Napi::ObjectWrap<NConnectionID> {
  private:
    std::unique_ptr<sispopmq::ConnectionID> instance;

  public:
    NConnectionID(const Napi::CallbackInfo& info) : Napi::ObjectWrap<NConnectionID>(info) {
        if (info.Length() != 1 || !info[0].IsExternal())
            throw std::logic_error{"ConnectionID is not directly constructible"};

        instance.reset(info[0].As<Napi::External<sispopmq::ConnectionID>>().Data());
    }

    static void napi_init(Napi::Env& env, Napi::Object& exports, ctors& ct) {
        Napi::Function func = DefineClass(
                env,
                "ConnectionID",
                {
                        InstanceAccessor("isServiceNode", &NConnectionID::isServiceNode, nullptr),
                        InstanceAccessor("pubkey", &NConnectionID::pubkey, nullptr),
                        InstanceMethod("equals", &NConnectionID::equals),
                        InstanceMethod("toString", &NConnectionID::toString),
                });

        ct.NConnectionID = Napi::Persistent(func);

        exports.Set("ConnectionID", func);
    }

    const sispopmq::ConnectionID& get() const { return *instance; }

    Napi::Value isServiceNode(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Boolean>(info, instance->sn());
    }

    Napi::Value pubkey(const Napi::CallbackInfo& info) {
        return napi_copy_bytes(info.Env(), instance->pubkey());
    }

    Napi::Value toString(const Napi::CallbackInfo& info) {
        std::ostringstream o;
        o << *instance;
        return napi_cast<Napi::String>(info, o.str());
    }

    Napi::Value equals(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        Napi::HandleScope scope{env};

        if (info.Length() != 1)
            throw std::invalid_argument{"equals() requires a ConnectionID argument"};

        auto* other = Unwrap(info[0].As<Napi::Object>());
        return Napi::Boolean::New(env, instance == other->instance);
    }

    // Copy a sispopmq::ConnectionID into a node-wrapped NConnectionID
    static Napi::Object wrap(const Napi::Env& env, const sispopmq::ConnectionID& conn) {
        return env.GetInstanceData<ctors>()->NConnectionID.New(
                {Napi::External<sispopmq::ConnectionID>::New(env, new sispopmq::ConnectionID{conn})});
    }

    friend class NMessage;
};

class NAddress : public Napi::ObjectWrap<NAddress> {
  private:
    sispopmq::address instance;

  public:
    NAddress(const Napi::CallbackInfo& info) : Napi::ObjectWrap<NAddress>(info) {
        auto env = info.Env();
        Napi::HandleScope scope{env};

        size_t length = info.Length();

        // Single string argument: construct an address from an encoded address such as
        // "curve://HOSTNAME:PORT/PUBKEY".
        if (length == 1 && info[0].IsString()) {
            std::string addr = info[0].ToString();
            instance = sispopmq::address{addr};
            return;
        }

        throw std::invalid_argument{
                "Invalid arguments: Address must be constructed with a single address string"};
    }
    static void napi_init(Napi::Env& env, Napi::Object& exports, ctors& ct) {
        Napi::HandleScope scope{env};

        Napi::Function func = DefineClass(
                env,
                "Address",
                {
                        InstanceAccessor("pubkey", &NAddress::pubkey, nullptr),
                        InstanceAccessor("curve", &NAddress::curve, nullptr),
                        InstanceAccessor("tcp", &NAddress::tcp, nullptr),
                        InstanceAccessor("ipc", &NAddress::ipc, nullptr),
                        InstanceAccessor("zmqAddress", &NAddress::zmqAddress, nullptr),
                        InstanceAccessor("fullAddress", &NAddress::fullAddress, nullptr),
                        InstanceAccessor("fullAddressB64", &NAddress::fullAddressB64, nullptr),
                        InstanceAccessor("fullAddressHex", &NAddress::fullAddressHex, nullptr),
                        InstanceAccessor("qr", &NAddress::qr, nullptr),
                        InstanceMethod("equals", &NAddress::equals),
                });

        ct.NAddress = Napi::Persistent(func);

        exports.Set("Address", func);
    }

    const sispopmq::address& get() const { return instance; }

    Napi::Value pubkey(const Napi::CallbackInfo& info) {
        return napi_copy_bytes(info.Env(), instance.pubkey);
    }
    Napi::Value curve(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Boolean>(info, instance.curve());
    }
    Napi::Value tcp(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Boolean>(info, instance.tcp());
    }
    Napi::Value ipc(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Boolean>(info, instance.ipc());
    }
    Napi::Value zmqAddress(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::String>(info, instance.zmq_address());
    }
    Napi::Value fullAddress(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::String>(
                info, instance.full_address(sispopmq::address::encoding::base32z));
    }
    Napi::Value fullAddressB64(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::String>(
                info, instance.full_address(sispopmq::address::encoding::base64));
    }
    Napi::Value fullAddressHex(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::String>(info, instance.full_address(sispopmq::address::encoding::hex));
    }
    Napi::Value qr(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::String>(info, instance.qr_address());
    }
    Napi::Value equals(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        Napi::HandleScope scope{env};

        if (info.Length() != 1)
            throw std::invalid_argument{"equals() requires an Address argument"};

        auto* other = Unwrap(info[0].As<Napi::Object>());
        return Napi::Boolean::New(env, instance == other->instance);
    }
};

// sispopmq::Message is designed to be ephemeral, used only in the callback.  That doesn't fit well at
// all with node, so we effectively copy the important data out of it.
class NMessage : public Napi::ObjectWrap<NMessage> {
  private:
    std::string remote_;
    Napi::TypedArrayOf<Napi::Buffer<uint8_t>> data_;
    // Holds the conn and reply tag for us; we don't currently use it to send things, but we could
    // in the future.
    std::optional<sispopmq::Message::DeferredSend> defer_;

  public:
    NMessage(const Napi::CallbackInfo& info) : Napi::ObjectWrap<NMessage>(info) {
        if (info.Length() != 1 || !info[0].IsExternal())
            throw std::logic_error{"Message is not directly constructible"};
        std::unique_ptr<sispopmq::Message> mptr{info[0].As<Napi::External<sispopmq::Message>>().Data()};
        auto env = info.Env();
        auto& m = *mptr;
        defer_.emplace(m.send_later());
        remote_ = std::move(m.remote);
        data_ = Napi::TypedArrayOf<Napi::Buffer<uint8_t>>::New(env, m.data.size());
        for (size_t i = 0; i < m.data.size(); i++)
            data_[i] = napi_copy_bytes(env, m.data[i]);
    }

    static void napi_init(Napi::Env& env, Napi::Object& exports, ctors& ct) {
        Napi::HandleScope scope{env};

        Napi::Function func = DefineClass(
                env,
                "Message",
                {
                        InstanceAccessor("isRequest", &NMessage::isRequest, nullptr),
                        InstanceAccessor("remoteAddress", &NMessage::remoteAddress, nullptr),
                        InstanceAccessor("conn", &NMessage::conn, nullptr),
                        // Returns a *copy* of the data; sispopmq exposes a view, but it's only valid
                        // for the duration of the callback itself.
                        InstanceAccessor("data", &NMessage::data, nullptr),
                });

        ct.NMessage = Napi::Persistent(func);

        exports.Set("Message", func);
    }

    Napi::Value isRequest(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Boolean>(info, !defer_->reply_tag.empty());
    }
    Napi::Value remoteAddress(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::String>(info, remote_);
    }
    Napi::Value conn(const Napi::CallbackInfo& info) {
        auto env = info.Env();
        auto c = env.GetInstanceData<ctors>()->NConnectionID.New(
                {Napi::External<sispopmq::ConnectionID>::New(
                        env, new sispopmq::ConnectionID{defer_->conn})});
        return c;
    }
    Napi::Value data(const Napi::CallbackInfo&) { return data_; }
};

class NSispopMQ : public Napi::ObjectWrap<NSispopMQ> {
    std::optional<sispopmq::SispopMQ> omq;

  public:
    NSispopMQ(const Napi::CallbackInfo& info) : Napi::ObjectWrap<NSispopMQ>(info) {
        // TODO: support various constructor invocations to map some of the things the SispopMQ
        // constructor supports.
        if (info.Length() != 0)
            throw std::logic_error{"SispopMQ constructor takes no arguments"};

        omq.emplace();
    }

    static void napi_init(Napi::Env& env, Napi::Object& exports, ctors& ct) {
        Napi::HandleScope scope{env};

        Napi::Function func = DefineClass(
                env,
                "SispopMQ",
                {
                        InstanceAccessor(
                                "handshakeMs", &NSispopMQ::handshake_time, &NSispopMQ::handshake_time),
                        InstanceAccessor(
                                "maxMessageSize", &NSispopMQ::max_msg_size, &NSispopMQ::max_msg_size),
                        InstanceAccessor(
                                "maxSockets", &NSispopMQ::max_sockets, &NSispopMQ::max_sockets),
                        InstanceAccessor(
                                "reconnectIntervalMs",
                                &NSispopMQ::reconnect_interval,
                                &NSispopMQ::reconnect_interval),
                        InstanceAccessor(
                                "maxReconnectIntervalMs",
                                &NSispopMQ::reconnect_interval_max,
                                &NSispopMQ::reconnect_interval_max),
                        InstanceAccessor(
                                "closeLingerMs", &NSispopMQ::close_linger, &NSispopMQ::close_linger),
                        InstanceAccessor(
                                "connCheckIntervalMs", &NSispopMQ::conn_check, &NSispopMQ::conn_check),
                        InstanceAccessor(
                                "connHeartbeatMs",
                                &NSispopMQ::conn_heartbeat,
                                &NSispopMQ::conn_heartbeat),
                        InstanceAccessor(
                                "connHeartbeatTimeoutMs",
                                &NSispopMQ::conn_heartbeat_timeout,
                                &NSispopMQ::conn_heartbeat_timeout),
                        InstanceAccessor("pubkey", &NSispopMQ::pubkey, nullptr),
                        InstanceAccessor("privkey", &NSispopMQ::privkey, nullptr),
                        InstanceMethod("start", &NSispopMQ::start),
                        InstanceMethod("connectRemote", &NSispopMQ::connect_remote),
                        InstanceMethod("connectRemoteAsync", &NSispopMQ::connect_remote_async),
                        InstanceMethod("disconnect", &NSispopMQ::disconnect),
                        InstanceMethod("request", &NSispopMQ::request),

                });

        ct.NSispopMQ = Napi::Persistent(func);

        exports.Set("SispopMQ", func);
    }

    void handshake_time(const Napi::CallbackInfo&, const Napi::Value& value) {
        omq->HANDSHAKE_TIME = std::chrono::milliseconds{value.As<Napi::Number>().Int64Value()};
    }
    Napi::Value handshake_time(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Number>(info, omq->HANDSHAKE_TIME.count());
    }
    void max_msg_size(const Napi::CallbackInfo&, const Napi::Value& value) {
        omq->MAX_MSG_SIZE = value.As<Napi::Number>().Int64Value();
    }
    Napi::Value max_msg_size(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Number>(info, omq->MAX_MSG_SIZE);
    }
    void max_sockets(const Napi::CallbackInfo&, const Napi::Value& value) {
        omq->MAX_SOCKETS = value.As<Napi::Number>().Int32Value();
    }
    Napi::Value max_sockets(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Number>(info, omq->MAX_SOCKETS);
    }
    void reconnect_interval(const Napi::CallbackInfo&, const Napi::Value& value) {
        omq->RECONNECT_INTERVAL = std::chrono::milliseconds{value.As<Napi::Number>().Int64Value()};
    }
    Napi::Value reconnect_interval(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Number>(info, omq->RECONNECT_INTERVAL.count());
    }
    void reconnect_interval_max(const Napi::CallbackInfo&, const Napi::Value& value) {
        omq->RECONNECT_INTERVAL_MAX =
                std::chrono::milliseconds{value.As<Napi::Number>().Int64Value()};
    }
    Napi::Value reconnect_interval_max(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Number>(info, omq->RECONNECT_INTERVAL_MAX.count());
    }
    void close_linger(const Napi::CallbackInfo&, const Napi::Value& value) {
        omq->CLOSE_LINGER = std::chrono::milliseconds{value.As<Napi::Number>().Int64Value()};
    }
    Napi::Value close_linger(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Number>(info, omq->CLOSE_LINGER.count());
    }
    void conn_check(const Napi::CallbackInfo&, const Napi::Value& value) {
        omq->CONN_CHECK_INTERVAL = std::chrono::milliseconds{value.As<Napi::Number>().Int64Value()};
    }
    Napi::Value conn_check(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Number>(info, omq->CONN_CHECK_INTERVAL.count());
    }
    void conn_heartbeat(const Napi::CallbackInfo&, const Napi::Value& value) {
        omq->CONN_HEARTBEAT = std::chrono::milliseconds{value.As<Napi::Number>().Int64Value()};
    }
    Napi::Value conn_heartbeat(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Number>(info, omq->CONN_HEARTBEAT.count());
    }
    void conn_heartbeat_timeout(const Napi::CallbackInfo&, const Napi::Value& value) {
        omq->CONN_HEARTBEAT_TIMEOUT =
                std::chrono::milliseconds{value.As<Napi::Number>().Int64Value()};
    }
    Napi::Value conn_heartbeat_timeout(const Napi::CallbackInfo& info) {
        return napi_cast<Napi::Number>(info, omq->CONN_HEARTBEAT_TIMEOUT.count());
    }
    Napi::Value pubkey(const Napi::CallbackInfo& info) {
        return napi_copy_bytes(info.Env(), omq->get_pubkey());
    }
    Napi::Value privkey(const Napi::CallbackInfo& info) {
        return napi_copy_bytes(info.Env(), omq->get_privkey());
    }
    void start(const Napi::CallbackInfo&) { omq->start(); }


    using ConnectResult = std::pair<sispopmq::ConnectionID, std::optional<std::string>>;
    // This function is indirectly invoked via a ThreadSafeConnectFunc (below) which is called from
    // a thread, queues the result, then calls *this* function in the main thread (from which we are
    // allowed to touch node):
    static void set_connect_result(
            Napi::Env env,
            Napi::Function /*callback*/,
            Napi::Promise::Deferred* context,
            ConnectResult* resultptr) {
        if (env == nullptr)
            return;

        const auto& [connid, failmsg] = *resultptr;
        if (!failmsg) {
            context->Resolve(NConnectionID::wrap(env, connid));
        } else {
            context->Reject(napi_cast<Napi::String>(env, *failmsg));
        }
        delete resultptr;
        delete context;
    }
    using ThreadSafeConnectFunc = Napi::TypedThreadSafeFunction<Napi::Promise::Deferred, ConnectResult, set_connect_result>;

    // The async version returns a promise that resolves to the ConnectionID, once a connection is
    // fully established.
    Napi::Value connect_remote_async(const Napi::CallbackInfo& info) {
        if (info.Length() < 1)
            throw std::invalid_argument{"An address is required"};
        NAddress* addr = NAddress::Unwrap(info[0].As<Napi::Object>());

        auto env = info.Env();
        auto* def = new Napi::Promise::Deferred(Napi::Promise::Deferred::New(env));

        auto f = ThreadSafeConnectFunc::New(
                env, "SispopMQ-Connect", 0, 1, def);

        auto on_success = [f](sispopmq::ConnectionID c) {
            f.BlockingCall(new ConnectResult{c, std::nullopt});
            f.Release();
        };
        auto on_failure = [f = std::move(f)](sispopmq::ConnectionID c, std::string_view reason) {
            f.BlockingCall(new ConnectResult{c, std::string{reason}});
            f.Release();
        };
        omq->connect_remote(addr->get(), on_success, on_failure);
        return def->Promise();
    }

    // The version starts establishing the connection and returns the ConnectionID immediately.
    // Messages send to the connection will be queued until the connection is established, then
    // sent.
    //
    // TODO: allow connect/connect_fail callbacks
    Napi::Value connect_remote(const Napi::CallbackInfo& info) {
        if (info.Length() < 1)
            throw std::invalid_argument{"An address is required"};
        NAddress* addr = NAddress::Unwrap(info[0].As<Napi::Object>());

        auto conn_id = omq->connect_remote(addr->get(), [](auto) {}, [](auto, auto) {});
        return NConnectionID::wrap(info.Env(), conn_id);
    }

    void disconnect(const Napi::CallbackInfo& info) {
        auto* conn = NConnectionID::Unwrap(info[0].As<Napi::Object>());
        omq->disconnect(conn->get());
    }

    static void relay_reply(
            Napi::Env env,
            Napi::Function /*callback*/,
            Napi::Promise::Deferred* def,
            std::pair<bool, std::vector<std::string>>* parts_ptr) {
        if (env == nullptr)
            return;

        const auto& [success, parts] = *parts_ptr;
        auto js_parts = Napi::Array::New(env, parts.size());
        for (size_t i = 0; i < parts.size(); i++)
            js_parts[i] = napi_copy_bytes(env, parts[i]);

        if (success)
            def->Resolve({js_parts});
        else
            def->Reject({js_parts});

        delete def;
    }
    using ThreadSafeReplyFunc = Napi::TypedThreadSafeFunction<
            Napi::Promise::Deferred,
            std::pair<bool, std::vector<std::string>>,
            relay_reply>;

    Napi::Value request(const Napi::CallbackInfo& info) {
        // Args:
        // - connid
        // - endpoint name, e.g. "category.command"
        // - array of data parts (Strings or Buffers); can be empty
        // - optional object of extra options:
        //   - "timeout" - how long (in ms) to wait for a reply before timing out (default 15s)
        //
        // Returns a promise; on success it gives you back an array of data parts, on failure it
        // gives you an array of error message data parts.

        auto env = info.Env();
        Napi::HandleScope scope{env};

        auto* conn = NConnectionID::Unwrap(info[0].As<Napi::Object>());

        auto endpoint = info[1].As<Napi::String>().Utf8Value();

        std::vector<std::string> parts_strs;
        std::vector<std::string_view> parts;
        auto data_in = info[2].As<Napi::Array>();
        for (size_t i = 0; i < data_in.Length(); i++) {
            Napi::Value in = data_in[i];
            if (in.IsString()) {
                parts_strs.push_back(in.As<Napi::String>().Utf8Value());
                parts.emplace_back(parts_strs.back());
            } else if (in.IsBuffer()) {
                auto ab = in.As<Napi::Buffer<char>>();
                parts.emplace_back(ab.Data(), ab.ByteLength());
            } else
                throw std::invalid_argument{
                        "Invalid argument: request data parts must be String or Buffer"};
        }

        auto def = new Napi::Promise::Deferred(Napi::Promise::Deferred::New(env));
        auto handle_reply = [reply_relay =
                                     ThreadSafeReplyFunc::New(env, "SispopMQ-Reply", 0, 1, def)](
                                    bool success, std::vector<std::string> data) {
            reply_relay.BlockingCall(new std::pair<bool, std::vector<std::string>>{
                    std::move(success), std::move(data)});
            reply_relay.Release();
        };

        sispopmq::send_option::request_timeout r_timeout{-1ms};
        if (info.Length() > 3) {
            auto opts = info[3].As<Napi::Object>();
            auto timeout = opts.Get("timeout");
            if (timeout.IsNumber())
                r_timeout.time = std::chrono::milliseconds{timeout.As<Napi::Number>().Int64Value()};
        }

        omq->request(
                conn->get(),
                endpoint,
                std::move(handle_reply),
                sispopmq::send_option::data_parts(parts),
                r_timeout);

        return def->Promise();
    }
};

}  // namespace nsispopmq

// The wonderful NODE_API macros break if given a namespaced init function, so here we provide a
// lovely top-level function that wraps the namespaced one.
Napi::Object sispopmq_module_init(Napi::Env env, Napi::Object exports) {
    auto* ctors = new nsispopmq::ctors{};
    nsispopmq::NConnectionID::napi_init(env, exports, *ctors);
    nsispopmq::NAddress::napi_init(env, exports, *ctors);
    nsispopmq::NMessage::napi_init(env, exports, *ctors);
    nsispopmq::NSispopMQ::napi_init(env, exports, *ctors);
    env.SetInstanceData(ctors);
    return exports;
}

NODE_API_MODULE(sispopmq, sispopmq_module_init)
