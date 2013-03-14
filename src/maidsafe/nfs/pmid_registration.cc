/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include "maidsafe/nfs/pmid_registration.h"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/nfs/generic_message_pb.h"


namespace maidsafe {

namespace nfs {

namespace {

template <typename InnerPubFobName, typename OuterPubFobName>
asymm::PlainText GetSerialisedDetails(const OuterPubFobName& outer_fob_name,
                                      const InnerPubFobName& inner_fob_name,
                                      bool unregister) {
  protobuf::FobPairRegistration::SignedDetails::Details details;
  details.set_outer_fob_name(outer_fob_name->string());
  details.set_inner_fob_name(inner_fob_name->string());
  details.set_unregister(unregister);
  return asymm::PlainText(details.SerializeAsString());
}

asymm::PlainText GetSerialisedSignedDetails(const asymm::PlainText& serialised_details,
                                            const asymm::Signature& inner_fob_signature) {
  protobuf::FobPairRegistration::SignedDetails signed_details;
  signed_details.set_serialised_details(serialised_details.string());
  signed_details.set_inner_fob_signature(inner_fob_signature.string());
  return asymm::PlainText(signed_details.SerializeAsString());
}

}  //  unnamed namespace

template <typename InnerFob, typename OuterFob, typename InnerPubFob, typename OuterPubFob>
FobPairRegistration<InnerFob, OuterFob, InnerPubFob, OuterPubFob>::FobPairRegistration(
    const OuterFob& outer_fob, const InnerFob& inner_fob, bool unregister)
    : outer_fob_name_(outer_fob.name()),
      inner_fob_name_(inner_fob.name()),
      unregister_(unregister),
      outer_fob_signature_(),
      inner_fob_signature_() {
  auto serialised_details(GetSerialisedDetails(outer_fob_name_, inner_fob_name_, unregister_));
  inner_fob_signature_ = asymm::Sign(serialised_details, inner_fob.private_key());

  auto serialised_signed_details(GetSerialisedSignedDetails(serialised_details,
                                                            outer_fob_signature_));
  outer_fob_signature_ = asymm::Sign(serialised_signed_details, outer_fob.private_key());
}

template <typename InnerFob, typename OuterFob, typename InnerPubFob, typename OuterPubFob>
FobPairRegistration<InnerFob, OuterFob, InnerPubFob, OuterPubFob>::FobPairRegistration(
    const std::string& serialised_fobpair_registration)
    : outer_fob_name_(),
      inner_fob_name_(),
      unregister_(),
      outer_fob_signature_(),
      inner_fob_signature_() {
  auto fail([]() {
    LOG(kError) << "Failed to parse fobpair_registration.";
    ThrowError(CommonErrors::parsing_error);
  });
  protobuf::FobPairRegistration proto_fobpair_registration;
  if (!proto_fobpair_registration.ParseFromString(serialised_fobpair_registration))
    fail();
  protobuf::FobPairRegistration::SignedDetails signed_details;
  if (!signed_details.ParseFromString(proto_fobpair_registration.serialised_signed_details()))
    fail();
  protobuf::FobPairRegistration::SignedDetails::Details details;
  if (!details.ParseFromString(signed_details.serialised_details()))
    fail();

  outer_fob_name_ = typename OuterFob::name_type(Identity(details.outer_fob_name()));
  inner_fob_name_ = typename InnerFob::name_type(Identity(details.inner_fob_name()));
  unregister_ = details.unregister();
  outer_fob_signature_ = asymm::Signature(proto_fobpair_registration.outer_fob_signature());
  inner_fob_signature_ = asymm::Signature(signed_details.inner_fob_signature());
}

template <typename InnerFob, typename OuterFob, typename InnerPubFob, typename OuterPubFob>
bool FobPairRegistration<InnerFob, OuterFob, InnerPubFob, OuterPubFob>::Validate(
    const OuterPubFob& public_outer_fob, const InnerPubFob& public_inner_fob) const {
  auto serialised_details(GetSerialisedDetails(outer_fob_name_, inner_fob_name_, unregister_));
  if (!asymm::CheckSignature(serialised_details,
                             inner_fob_signature_,
                             public_inner_fob.public_key())) {
    LOG(kWarning) << "Failed to validate InnerFob signature.";
    return false;
  }
  auto serialised_signed_details(GetSerialisedSignedDetails(serialised_details,
                                                            inner_fob_signature_));
  if (!asymm::CheckSignature(serialised_signed_details, outer_fob_signature_,
                             public_outer_fob.public_key())) {
    LOG(kWarning) << "Failed to validate OuterFob signature.";
    return false;
  }
  return true;
}

template <typename InnerFob, typename OuterFob, typename InnerPubFob, typename OuterPubFob>
std::string FobPairRegistration<InnerFob, OuterFob,
                                InnerPubFob, OuterPubFob>::SerialiseAsString() const {
  protobuf::FobPairRegistration proto_fobpair_registration;
  proto_fobpair_registration.set_serialised_signed_details(
      GetSerialisedSignedDetails(
          GetSerialisedDetails(outer_fob_name_, inner_fob_name_, unregister_),
          inner_fob_signature_).string());
  proto_fobpair_registration.set_outer_fob_signature(outer_fob_signature_.string());
  return proto_fobpair_registration.SerializeAsString();
}

}  // namespace nfs

}  // namespace maidsafe
