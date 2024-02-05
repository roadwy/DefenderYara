
rule Trojan_Win32_TrickBotCrypt_GF_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 0a 33 d2 03 c3 f7 35 90 01 04 b8 02 00 00 00 2b c7 0f af c7 8b f9 03 fa 8a 14 38 8b 44 24 18 8a 18 32 da 8b 54 24 20 88 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}