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

#ifndef MAIDSAFE_NFS_CLIENT_POST_POLICIES_H_
#define MAIDSAFE_NFS_CLIENT_POST_POLICIES_H_

#include <string>

#include "maidsafe/routing/routing_api.h"

#include "maidsafe/nfs/generic_message.h"
#include "maidsafe/nfs/message.h"
#include "maidsafe/nfs/persona_id.h"

namespace maidsafe {

namespace nfs {

template<typename SigningFob>
class NoPost {
 public:
  NoPost() {}
  NoPost(routing::Routing&, const SigningFob&) {}
  template<typename Data>
  void Post(const typename Data::name_type& /*name*/) {}

 protected:
  ~NoPost() {}
};

template <typename SigningFob, Persona source_persona>
class ClientPostPolicy {
 public:
  ClientPostPolicy(routing::Routing& routing, const SigningFob& signing_fob)
      : routing_(routing),
        kSigningFob_(new SigningFob(signing_fob)),
        kSource_(source_persona, routing_.kNodeId()) {}

 protected:
  routing::Routing& routing_;
  const std::unique_ptr<const SigningFob> kSigningFob_;
  const PersonaId kSource_;
};


class ClientMaidPostPolicy : ClientPostPolicy<passport::Maid, Persona::kClientMaid> {
 public:
  ClientMaidPostPolicy(routing::Routing& routing, const passport::Maid& signing_fob)
    : ClientPostPolicy<passport::Maid, Persona::kClientMaid>(routing, signing_fob) {}

  void RegisterPmid(const NonEmptyString& serialised_pmid_registration,
                    const routing::ResponseFunctor& callback) {
    GenericMessage generic_message(
        nfs::GenericMessage::Action::kRegisterPmid,
        Persona::kClientMaid,
        kSource_,
        kSigningFob_->name().data,
        serialised_pmid_registration);
    Message message(GenericMessage::message_type_identifier, generic_message.Serialise().data);
    routing_.SendGroup(NodeId(generic_message.name().string()), message.Serialise()->string(),
                       false, callback);
  }

  void UnregisterPmid(const NonEmptyString& serialised_pmid_unregistration,
                      const routing::ResponseFunctor& callback) {
    GenericMessage generic_message(
        nfs::GenericMessage::Action::kUnregisterPmid,
        Persona::kClientMaid,
        kSource_,
        kSigningFob_->name().data,
        serialised_pmid_unregistration);
    Message message(GenericMessage::message_type_identifier, generic_message.Serialise().data);
    routing_.SendGroup(NodeId(generic_message.name().string()), message.Serialise()->string(),
                       false, callback);
  }
};

class ClientMpidPostPolicy : ClientPostPolicy<passport::Mpid, Persona::kClientMpid> {
 public:
  ClientMpidPostPolicy(routing::Routing& routing, const passport::Mpid& signing_fob)
    : ClientPostPolicy<passport::Mpid, Persona::kClientMpid>(routing, signing_fob) {}

  void RegisterMpid(const NonEmptyString& serialised_mpid_registration,
                    const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(MessageToMPAH::Action::kRegisterMpid,
                                  kSigningFob_->name(),
                                  serialised_mpid_registration);
    SendMessage(message_to_mpah.Serialise(), callback);
  }
  void UnRegisterMpid(const NonEmptyString& serialised_mpid_registration,
                      const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(MessageToMPAH::Action::kUnregisterMpid,
                                  kSigningFob_->name(),
                                  serialised_mpid_registration);
    SendMessage(message_to_mpah.Serialise(), callback);
  }
  void GoOffline(const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(MessageToMPAH::Action::kClientDown, kSigningFob_->name());
    SendMessage(message_to_mpah.Serialise(), callback);
  }
  void GoOnline(const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(MessageToMPAH::Action::kClientUp, kSigningFob_->name());
    SendMessage(message_to_mpah.Serialise(), callback);
  }
  void GetOfflineMsg(const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(MessageToMPAH::Action::kGetOfflineMsg, kSigningFob_->name());
    SendMessage(message_to_mpah.Serialise(), callback);
  }
  void AddContact(const NonEmptyString& contact, const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(
        MessageToMPAH::Action::kAddContact, kSigningFob_->name(), contact);
    SendMessage(message_to_mpah.Serialise(), callback);
  }
  void BlockContact(const NonEmptyString& contact, const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(
        MessageToMPAH::Action::kBlockContact, kSigningFob_->name(), contact);
    SendMessage(message_to_mpah.Serialise(), callback);
  }
  void MarkSpamContact(const NonEmptyString& contact, const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(
        MessageToMPAH::Action::kMarkSpamContact, kSigningFob_->name(), contact);
    SendMessage(message_to_mpah.Serialise(), callback);
  }
  void UnMarkSpamContact(const NonEmptyString& contact,
                         const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(
        MessageToMPAH::Action::kUnMarkSpamContact, kSigningFob_->name(), contact);
    SendMessage(message_to_mpah.Serialise(), callback);
  }
  void RemoveContact(const NonEmptyString& contact, const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(
        MessageToMPAH::Action::kRemoveContact, kSigningFob_->name(), contact);
    SendMessage(message_to_mpah.Serialise(), callback);
  }
  void GetContactList(const routing::ResponseFunctor& callback) {
    MessageToMPAH message_to_mpah(MessageToMPAH::Action::kGetContactList, kSigningFob_->name());
    SendMessage(message_to_mpah.Serialise(), callback);
  }

 private:
  void SendMessage(const NonEmptyString& serialised_message,
                   const routing::ResponseFunctor& callback) {
    GenericMessage generic_message(
        nfs::GenericMessage::Action::kMsgToMPAH,
        Persona::kClientMpid,
        kSource_,
        kSigningFob_->name().data,
        serialised_message);
    Message message(GenericMessage::message_type_identifier, generic_message.Serialise().data);
    routing_.SendGroup(NodeId(generic_message.name().string()), message.Serialise()->string(),
                       false, callback);
  }
};

}  // namespace nfs

}  // namespace maidsafe

#include "maidsafe/nfs/client_post_policies-inl.h"

#endif  // MAIDSAFE_NFS_CLIENT_POST_POLICIES_H_
