
rule Trojan_Win32_TrickBotCrypt_YAB_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 4d e4 8b 4d 08 03 4d e8 0f b6 11 8b 45 e4 0f b6 8c 05 90 01 04 33 d1 8b 45 18 03 45 e8 88 10 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}