
rule Trojan_Win32_TrickbotCrypt_KM_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 c2 3b 15 00 00 89 95 90 01 04 8b 85 90 01 04 2b 85 90 01 04 89 85 90 01 04 8b 8d 90 01 04 81 e9 00 f0 0f 0f 89 8d 90 01 04 8b 95 90 01 04 8b 85 90 01 04 8b 8d 90 01 04 89 0c 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}