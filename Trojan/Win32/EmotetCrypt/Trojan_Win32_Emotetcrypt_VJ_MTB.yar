
rule Trojan_Win32_Emotetcrypt_VJ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 2b 05 [0-04] 47 03 c8 0f b6 c3 8b 1d [0-04] 8a 04 [0-01] 30 01 8b 4d [0-01] 3b fe } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VJ_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c3 99 b9 [0-04] f7 [0-02] 88 [0-32] 8b 55 [0-02] 81 e2 ff 00 00 00 8b 45 [0-02] 03 45 [0-02] 8b 0d [0-04] 8a 00 32 04 11 8b 4d [0-02] 03 4d [0-02] 88 01 e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}