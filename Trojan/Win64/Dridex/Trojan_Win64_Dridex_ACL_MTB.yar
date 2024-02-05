
rule Trojan_Win64_Dridex_ACL_MTB{
	meta:
		description = "Trojan:Win64/Dridex.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {e2 71 29 c7 7b 56 9d fa b4 46 08 4b 3e e4 b5 43 97 5b 4c 29 d3 83 6f 0a 35 b2 5d 94 a2 a7 6d ba } //03 00 
		$a_80_1 = {55 75 69 64 49 73 4e 69 6c } //UuidIsNil  03 00 
		$a_80_2 = {43 72 79 70 74 43 41 54 50 75 74 41 74 74 72 49 6e 66 6f } //CryptCATPutAttrInfo  03 00 
		$a_80_3 = {43 6f 70 79 45 6e 68 4d 65 74 61 46 69 6c 65 57 } //CopyEnhMetaFileW  03 00 
		$a_80_4 = {43 72 65 61 74 65 44 69 73 63 61 72 64 61 62 6c 65 42 69 74 6d 61 70 } //CreateDiscardableBitmap  03 00 
		$a_80_5 = {55 72 6c 55 6e 65 73 63 61 70 65 41 } //UrlUnescapeA  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Dridex_ACL_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.ACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {ff d0 e8 f2 ff ff ff 90 09 33 00 4c 31 25 90 01 04 48 31 15 90 01 04 48 31 25 90 01 04 48 31 1d 90 01 04 4c 31 0d 90 01 04 48 8b 05 90 01 04 eb 09 4c 31 2d 90 00 } //03 00 
		$a_80_1 = {47 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 57 } //GetUrlCacheEntryInfoW  03 00 
		$a_80_2 = {41 73 73 6f 63 69 61 74 65 43 6f 6c 6f 72 50 72 6f 66 69 6c 65 57 69 74 68 44 65 76 69 63 65 57 } //AssociateColorProfileWithDeviceW  03 00 
		$a_80_3 = {43 72 79 70 74 43 41 54 50 75 74 41 74 74 72 49 6e 66 6f } //CryptCATPutAttrInfo  03 00 
		$a_80_4 = {53 74 72 54 72 69 6d 57 } //StrTrimW  00 00 
	condition:
		any of ($a_*)
 
}