# Design and Architecture of the eCTF Challenge

## Functional Requirements

### Encoder
```
EncodedFrame {
  ChannelNumber,
  Timestamp,
  TVFrame,
  GlobalSecrets
}
```

### Decoder

#### List Channels
The Decoder must be able to list the channel numbers that the Decoder has a valid subscription for.

#### Update Subcriptions
To decode TV frame data, the Decoder must have a valid subscription for that channel. The Decoder must be able to update it’s channel subscriptions with a valid update package. If a subscription update for a channel is received for a channel that already has a subscription, the Decoder must only use the latest subscription update. There is no subscription update associated with the emergency broadcast channel (channel 0). Frames received on this channel must always be properly decoded.

#### Decode Frame
Must be able to decode any frame with a valid subscription, as well as the emergency channel (0)

## Security Requirements
