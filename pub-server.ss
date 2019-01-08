(import :std/format
        :thunknyc/zmq)

(def c (ctx-new))
(def s (socket c ZMQ_PUB))
(bind s "tcp://*:5556")
(let lp ()
  (let* ((topic (+ 100 (random-integer 10)))
         (message (+ 1000 (random-integer 1000)))
         (body (format "~A ~A" topic message)))
    (printf "Message: ~S\n" body)
    (send-string s body 0)
    (thread-sleep! 1)
    (lp)))
