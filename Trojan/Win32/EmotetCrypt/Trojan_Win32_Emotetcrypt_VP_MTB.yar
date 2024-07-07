
rule Trojan_Win32_Emotetcrypt_VP_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 90 01 01 c7 45 90 01 05 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 c7 45 90 01 05 c7 45 90 01 05 c7 45 90 01 05 8b 4d 90 01 01 83 90 01 02 0f af 4d 90 01 01 8b 45 90 01 01 99 f7 f9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VP_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 90 02 02 8b 0d 90 02 04 8b 44 90 02 02 8a 14 90 02 02 30 14 90 02 02 8b 44 90 02 02 43 3b d8 0f 8c 90 02 04 8a 90 02 04 8b 90 02 04 8a 90 02 04 5f 90 02 02 88 90 02 02 88 90 02 02 5b 59 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}