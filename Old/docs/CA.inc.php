    $hExts = array (
       "basicConstraints"=>"CA:FALSE",
       "keyUsage"=>"nonRepudiation,digitalSignature,keyEncipherment",
       "nsComment"=>"Rheoli CA Server Certificate",
       "subjectKeyIdentifier"=>"hash",
       "authorityKeyIdentifier"=>"keyid,issuer:always",
       "nsCaRevocationUrl"=>"https://phpca.rheoli.ws/phpCA/class".$this->iClass."/getcrl.php",
       "nsRevocationUrl"=>"https://phpca.rheoli.ws/phpCA/class".$this->iClass."/getcrl.php",
       "nsRenewalUrl"=>"https://phpca.rheoli.ws/phpCA/class".$this->iClass."/renewal.php" );
    if ( $_iType == phpCA_CA_ServerCert ) {
      $hExts["nsCertType"] = "server";
    }
    if ( $_iType == phpCA_CA_AuthCert ) {
      $hExts["nsCertType"] = "client";
    }
    if ( $_iType == phpCA_CA_EmailCert ) {
      $hExts["nsCertType"] = "email";
    }
    // "subjectAltName"=>"email:copy"
    // "issuerAltName"=>"issuer:copy"
    return ( $hExts );
  }
