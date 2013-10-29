/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_NFS_MESSAGE_WRAPPER_H_
#define MAIDSAFE_NFS_MESSAGE_WRAPPER_H_

#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include "maidsafe/common/utils.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/nfs/types.h"

namespace maidsafe {

namespace nfs {

namespace detail {

struct SourceTag;
struct DestinationTag;
typedef TaggedValue<Persona, struct detail::SourceTag> SourceTaggedValue;
typedef TaggedValue<Persona, struct detail::DestinationTag> DestinationTaggedValue;

}  // namespace detail

typedef std::tuple<MessageAction, detail::SourceTaggedValue, detail::DestinationTaggedValue,
                   MessageId, std::string> TypeErasedMessageWrapper;

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
struct MessageWrapper {
  typedef SourcePersonaType SourcePersona;
  typedef RoutingSenderType Sender;
  typedef DestinationPersonaType DestinationPersona;
  typedef RoutingReceiverType Receiver;
  typedef ContentsType Contents;

  MessageWrapper();

  // For use with new messages (a new message_id is automatically applied).
  explicit MessageWrapper(const ContentsType& contents_in);

  // For use with new messages.
  MessageWrapper(MessageId message_id_in, ContentsType contents_in);

  // For use when handling incoming messages where the sender has already set the message_id.
  explicit MessageWrapper(const TypeErasedMessageWrapper& parsed_message_wrapper);

  MessageWrapper(const MessageWrapper& other);
  MessageWrapper(MessageWrapper&& other);
  MessageWrapper& operator=(MessageWrapper other);

  std::string Serialise() const;

  friend void swap(MessageWrapper& lhs, MessageWrapper& rhs) {
    using std::swap;
    swap(lhs.message_id, rhs.message_id);
    swap(lhs.contents, rhs.contents);
  }

  MessageId message_id;
  std::shared_ptr<ContentsType> contents;

 private:
  static const detail::SourceTaggedValue kSourceTaggedValue;
  static const detail::DestinationTaggedValue kDestinationTaggedValue;
};

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
bool operator==(
    const MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
                         RoutingReceiverType, ContentsType>& lhs,
    const MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
                         RoutingReceiverType, ContentsType>& rhs) {
  LOG(kVerbose) << "comparing two messages : lhs message_id -- " << lhs.message_id.data
                << " rhs message_id -- " << rhs.message_id.data;
  if (lhs.message_id != rhs.message_id) {
    LOG(kInfo) << "message_id mismatch";
    return false;
  }
  if ((!lhs.contents && rhs.contents) || (lhs.contents && !rhs.contents)) {
    LOG(kInfo) << "one of the message having empty content";
    return false;
  }
  if (lhs.contents)
    return *lhs.contents == *rhs.contents;
  return true;
}
TypeErasedMessageWrapper ParseMessageWrapper(const std::string& serialised_message_wrapper);

// ==================== Implementation =============================================================
namespace detail {

MessageId GetNewMessageId();

std::string SerialiseMessageWrapper(const TypeErasedMessageWrapper& message_tuple);

}  // namespace detail

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
const detail::SourceTaggedValue MessageWrapper<
    action, SourcePersonaType, RoutingSenderType, DestinationPersonaType, RoutingReceiverType,
    ContentsType>::kSourceTaggedValue = detail::SourceTaggedValue(SourcePersonaType::value);

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
const detail::DestinationTaggedValue
    MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
                   RoutingReceiverType, ContentsType>::kDestinationTaggedValue =
        detail::DestinationTaggedValue(DestinationPersonaType::value);

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
               RoutingReceiverType, ContentsType>::MessageWrapper()
    : message_id(detail::GetNewMessageId()), contents() {}

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
               RoutingReceiverType, ContentsType>::MessageWrapper(const ContentsType& contents_in)
    : message_id(detail::GetNewMessageId()),
      contents(std::make_shared<ContentsType>(contents_in)) {}

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
               RoutingReceiverType, ContentsType>::MessageWrapper(MessageId message_id_in,
                                                                  ContentsType contents_in)
    : message_id(std::move(message_id_in)), contents(std::make_shared<ContentsType>(contents_in)) {}

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
               RoutingReceiverType,
               ContentsType>::MessageWrapper(const TypeErasedMessageWrapper& parsed_message_wrapper)
    : message_id(std::get<3>(parsed_message_wrapper)),
      contents(std::make_shared<ContentsType>(std::get<4>(parsed_message_wrapper))) {}

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
               RoutingReceiverType, ContentsType>::MessageWrapper(const MessageWrapper& other)
    : message_id(other.message_id), contents(other.contents) {}

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
               RoutingReceiverType, ContentsType>::MessageWrapper(MessageWrapper&& other)
    : message_id(std::move(other.message_id)), contents(std::move(other.contents)) {}

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
               RoutingReceiverType, ContentsType>&
MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
               RoutingReceiverType, ContentsType>::
operator=(MessageWrapper other) {
  swap(*this, other);
  return *this;
}

template <MessageAction action, typename SourcePersonaType, typename RoutingSenderType,
          typename DestinationPersonaType, typename RoutingReceiverType, typename ContentsType>
std::string MessageWrapper<action, SourcePersonaType, RoutingSenderType, DestinationPersonaType,
                           RoutingReceiverType, ContentsType>::Serialise() const {
  return detail::SerialiseMessageWrapper(std::make_tuple(
      action, kSourceTaggedValue, kDestinationTaggedValue, message_id, contents->Serialise()));
}

}  // namespace nfs

}  // namespace maidsafe

#endif  // MAIDSAFE_NFS_MESSAGE_WRAPPER_H_
