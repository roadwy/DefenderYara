
rule Trojan_Win32_Trickbotcrypt_RTB_MTB{
	meta:
		description = "Trojan:Win32/Trickbotcrypt.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 9d 63 0f 8b 44 24 90 01 01 89 c1 81 e9 30 fd 0d 84 89 44 24 90 01 01 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}