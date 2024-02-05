
rule Trojan_Win32_TrickBotCrypt_EF_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 02 80 f1 80 3b c6 73 21 8d 9b 90 01 04 8a d0 2a d3 80 e2 80 32 10 32 d1 88 10 03 c7 3b c6 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBotCrypt_EF_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 32 34 e0 8b ce 3b f7 73 90 02 06 8a d1 2a d3 80 e2 e0 32 11 32 d0 88 11 03 4d f4 3b cf 72 90 01 01 8b 55 f8 46 ff 4d fc 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}