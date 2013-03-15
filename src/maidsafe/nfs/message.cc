/***************************************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#include "maidsafe/nfs/message.h"

#include "maidsafe/common/error.h"

#include "maidsafe/nfs/message_pb.h"


namespace maidsafe {

namespace nfs {

Message::Message(MessageCategory inner_message_type,
                 const NonEmptyString& serialised_inner_message,
                 const asymm::Signature& signature)
    : inner_message_type_(inner_message_type),
      serialised_inner_message_(serialised_inner_message),
      signature_(signature) {}

Message::Message(const Message& other)
    : inner_message_type_(other.inner_message_type_),
      serialised_inner_message_(other.serialised_inner_message_),
      signature_(other.signature_) {}

Message& Message::operator=(const Message& other) {
  inner_message_type_ = other.inner_message_type_;
  serialised_inner_message_ = other.serialised_inner_message_;
  signature_ = other.signature_;
  return *this;
}

Message::Message(Message&& other)
    : inner_message_type_(std::move(other.inner_message_type_)),
      serialised_inner_message_(std::move(other.serialised_inner_message_)),
      signature_(std::move(other.signature_)) {}

Message& Message::operator=(Message&& other) {
  inner_message_type_ = std::move(other.inner_message_type_);
  serialised_inner_message_ = std::move(other.serialised_inner_message_);
  signature_ = std::move(other.signature_);
  return *this;
}

Message::Message(const serialised_type& serialised_message)
    : inner_message_type_(static_cast<MessageCategory>(-1)),
      serialised_inner_message_(),
      signature_() {
  protobuf::Message proto_message;
  if (!proto_message.ParseFromString(serialised_message->string()))
    ThrowError(CommonErrors::parsing_error);
  inner_message_type_ = static_cast<MessageCategory>(proto_message.message_type());
  serialised_inner_message_ = NonEmptyString(proto_message.serialised_message());
  if (proto_message.has_signature())
    signature_ = asymm::Signature(proto_message.signature());
}

Message::serialised_type Message::Serialise() const {
  serialised_type serialised_message;
  try {
    protobuf::Message proto_message;
    proto_message.set_message_type(static_cast<int32_t>(inner_message_type_));
    proto_message.set_serialised_message(serialised_inner_message_.string());
    serialised_message = serialised_type(NonEmptyString(proto_message.SerializeAsString()));
    if (signature_.IsInitialised())
      proto_message.set_signature(signature_.string());
  }
  catch(const std::exception&) {
    ThrowError(NfsErrors::invalid_parameter);
  }
  return serialised_message;
}

MessageList::MessageList(const serialised_type& serialised_message)
    : message_list_() {
  protobuf::MessageList proto_message_list;
  if (!proto_message_list.ParseFromString(serialised_message->string()))
    ThrowError(CommonErrors::parsing_error);
  for (int i(0); i < proto_message_list.messages_size(); ++i) {
    Message msg(Message::serialised_type(NonEmptyString(
        proto_message_list.messages(i).SerializeAsString())));
    message_list_.push_back(std::move(msg));
  }
}

MessageList::serialised_type MessageList::Serialise() const {
  protobuf::MessageList proto_message_list;
  for (auto &message : message_list_) {
    auto entry = proto_message_list.add_messages();
    entry->ParseFromString(message.Serialise()->string());
  }
  return serialised_type(NonEmptyString(proto_message_list.SerializeAsString()));
}

}  // namespace nfs

}  // namespace maidsafe
