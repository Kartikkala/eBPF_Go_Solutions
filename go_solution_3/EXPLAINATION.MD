Explain what the following code is attempting to do? You can explain by:
1. Explaining how the highlighted constructs work?
2. Giving use-cases of what these constructs could be used for.
3. What is the significance of the for loop with 4 iterations?
4. What is the significance of make(chan func(), 10)?
5. Why is “HERE1” not getting printed?

The following code is trying to create a worker pool of 4 workers. Here's an answer to all of these questions

1. First we have a make statement that creates a function channel of size 10 (buffered channel). Then we have a for loop from 0-3 that creates 4 gorutines.
Each goroutine has a <code>for f := range cnp</code> (which is a way to pause and wait to take input from the cnp function channel). Means all 4 gorutines will pause
until there's a function put into that channel cnp. Inside the for body, f() (the function recieved from the channel) is called. Which only happens after 
we get a function from that channel. Then immediately we are trying to put a function to that channel by <code>cnp <-func() {...body...}</code>.
And the println is printing hello.

2. This pattern is used for creating a worker pool (where we want not more than n workers) to do multiple tasks simultaneously. For example, I have used this pattern
in my Cloud Drive 2.0 project for creating ffmpeg workers to convert .mp4 video files to HLS compatible media files.

3. The loop is there to fire n gorutines (4 in this case). The channel has a max buffer capacity of 10, that means we can bump n of the for loop upto 10 as well.

4. <code>make(chan func(), 10)</code> is used to create a buffered channel of capacity 10. This allows our multiple gorutines to take atleast 10 inputs/functions simultaneously.
If we would have used single channel, that would have caused the sender (<code>cnp <- func(){...body...}</code>) to pause until a goroutine is ready to take their job (when all 4
workers are busy, then the sender would have to pause).

5. HERE1 is not getting printed because the program is exiting too early for the goroutine to take the func from the channel and run it. To solve this, I have added an os signal
to wait for SIGTERM (CTRL-C) command from OS to exit. Generally for worker pools, waitgroups are used for tracking if all the gorutines have finished or not.
