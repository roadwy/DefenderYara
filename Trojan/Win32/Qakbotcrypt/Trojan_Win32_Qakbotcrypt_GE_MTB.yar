
rule Trojan_Win32_Qakbotcrypt_GE_MTB{
	meta:
		description = "Trojan:Win32/Qakbotcrypt.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 14 32 88 14 01 a1 90 01 04 83 c0 01 a3 90 01 04 eb 90 0a 32 00 03 05 90 01 04 8b 0d 90 01 04 8b 15 90 00 } //0a 00 
		$a_02_1 = {8b 0d 8b 11 89 15 90 02 64 33 90 01 01 8b c2 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}