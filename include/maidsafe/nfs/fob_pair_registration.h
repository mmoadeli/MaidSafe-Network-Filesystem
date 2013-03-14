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

#ifndef MAIDSAFE_NFS_FOB_PAIR_REGISTRATION_H_
#define MAIDSAFE_NFS_FOB_PAIR_REGISTRATION_H_

#include <string>

#include "maidsafe/common/types.h"

#include "maidsafe/passport/types.h"


namespace maidsafe {

namespace nfs {

template <typename InnerFob, typename OuterFob, typename InnerPubFob, typename OuterPubFob>
class FobPairRegistration {
 public:
  bool Validate(const OuterPubFob& public_outer_fob,
                const InnerPubFob& public_inner_fob) const;
  std::string SerialiseAsString() const;
  bool unregister() const { return unregister_; }

 protected:
  typename InnerFob::name_type inner_fob_name() const { return inner_fob_name_; }
  typename OuterFob::name_type outer_fob_name() const { return outer_fob_name_; }
  FobPairRegistration(const OuterFob& outer_fob,
                      const InnerFob& inner_fob,
                      bool unregister);
  explicit FobPairRegistration(const std::string& serialised_fobpair_registration);

 private:
  typename OuterPubFob::name_type outer_fob_name_;
  typename InnerPubFob::name_type inner_fob_name_;
  bool unregister_;
  asymm::Signature outer_fob_signature_;
  asymm::Signature inner_fob_signature_;
};

class PmidRegistration : FobPairRegistration
  <passport::Pmid, passport::Maid, passport::PublicPmid, passport::Maid> {
 public:
  typedef TaggedValue<NonEmptyString, struct SerialisedPmidRegistrationTag> serialised_type;

  PmidRegistration(const passport::Maid& maid, const passport::Pmid& pmid, bool unregister)
    : FobPairRegistration(maid, pmid, unregister) {}
  explicit PmidRegistration(const serialised_type& serialised_pmid_registration)
    : FobPairRegistration(serialised_pmid_registration->string()) {}

  passport::PublicMaid::name_type maid_name() const { return outer_fob_name(); }
  passport::PublicPmid::name_type pmid_name() const { return inner_fob_name(); }
  serialised_type Serialise() const {
    return serialised_type(NonEmptyString(SerialiseAsString()));
  }
};

class MpidRegistration : FobPairRegistration
  <passport::Mpid, passport::Anmpid, passport::PublicMpid, passport::Anmpid> {
 public:
  typedef TaggedValue<NonEmptyString, struct SerialisedMpidRegistrationTag> serialised_type;

  MpidRegistration(const passport::Anmpid& anmpid, const passport::Mpid& mpid, bool unregister)
    : FobPairRegistration(anmpid, mpid, unregister) {}
  explicit MpidRegistration(const serialised_type& serialised_mpid_registration)
    : FobPairRegistration(serialised_mpid_registration->string()) {}

  passport::PublicAnmpid::name_type anmpid_name() const { return outer_fob_name(); }
  passport::PublicMpid::name_type mpid_name() const { return inner_fob_name(); }
  serialised_type Serialise() const {
    return serialised_type(NonEmptyString(SerialiseAsString()));
  }
};

}  // namespace nfs

}  // namespace maidsafe

#endif  // MAIDSAFE_NFS_FOB_PAIR_REGISTRATION_H_
