
rule Trojan_Win32_TrickBotCrypt_DP_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 11 0f b6 45 90 01 01 33 d0 8b 4d 90 01 01 2b 4d 90 01 01 0f b6 c1 25 80 00 00 00 33 d0 8b 4d 90 01 01 88 11 8b 55 90 01 01 03 55 90 01 01 89 55 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}