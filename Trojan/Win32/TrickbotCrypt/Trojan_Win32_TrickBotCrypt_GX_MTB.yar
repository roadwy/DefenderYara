
rule Trojan_Win32_TrickBotCrypt_GX_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 14 3e 8b c6 83 e0 1f 8a 0c 28 32 d1 88 14 3e 46 3b f3 75 } //01 00 
		$a_81_1 = {51 61 40 66 78 59 52 7a 2a 4e 24 34 78 75 30 4e 6c 33 24 68 79 58 44 33 39 49 44 53 7b 32 34 } //00 00 
	condition:
		any of ($a_*)
 
}