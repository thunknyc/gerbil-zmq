(import :std/format
        :thunknyc/zmq)

(def c (ctx-new))
(def s (socket c ZMQ_SUB))
(connect s "tcp://localhost:5556")
(subscribe s "100")
(let lp ()
  (let (message (receive s 128))
    (when message (printf "Got a message: ~S\n" message))
    (lp)))
