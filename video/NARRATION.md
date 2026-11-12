# Voice-over

The voice-over for the two-minute video, one numbered line per recording. Each line starts at the time in bold; the pictures and the captions follow the same times (see `SHOTS.md`). The lines hold no measured numbers: every result appears on screen, read from the result files when the frames are captured.

Spoken at 150 words a minute the lines take about 1:35 of the 1:53 the video runs, and each line ends with a pause before the next one starts.

## Lines

### Shot 1. The attack

1. **0:00.0** This is Sealed, the alert explainer I built for Track 4.
2. **0:04.3** The username is attacker-controlled, so I'm pasting an instruction in.
3. **0:08.7** A normal AI explainer reads it, and lowers its decision.
4. **0:13.0** Sealed keeps the same action, and its model input doesn't change.
5. **0:18.5** Here's the count across the whole test run.

### Shot 2. How it works

6. **0:22.5** How it works: a strict parser keeps only signals from a fixed vocabulary.
7. **0:29.0** A fixed policy decides the action, and the model only explains those facts, citing each one.
8. **0:36.3** Usernames and URLs go around the model into quarantine, and instruction-like text raises the alert instead.

### Shot 3. Results

9. **0:44.5** I tested this with three local models on synthetic alerts.
10. **0:50.2** Each one ran a raw prompt, a hardened prompt, and Sealed.
11. **0:54.7** These columns show how often the decision changed under attack.
12. **1:00.2** For Sealed, the model input stayed identical, and the action can only go up, never down.
13. **1:07.8** One honest miss: the detector didn't flag this base64 string, but the model still never saw it.

### Shot 4. Run it

14. **1:16.0** Everything runs offline, with one command and no API keys.
15. **1:20.5** The demo ends with the seal check: both alerts, same hash.
16. **1:26.0** The tests push thousands of random values through every free-text field.

### Shot 5. Try to break it

17. **1:31.0** You can try it yourself. Here I'm typing a Hinglish attack.
18. **1:36.5** The action doesn't go down, and the model input hash is unchanged.

### Shot 6. Limits

19. **1:42.5** Limitations: the alerts are synthetic, and the explanations haven't been tested with real analysts yet. Thanks for watching.

The video ends at **1:53.0**, after 10.5 seconds on the end card.
