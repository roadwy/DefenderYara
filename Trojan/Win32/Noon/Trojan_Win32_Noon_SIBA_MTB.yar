
rule Trojan_Win32_Noon_SIBA_MTB{
	meta:
		description = "Trojan:Win32/Noon.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4c 65 78 78 40 62 61 6b 6c 61 6e 6f 76 2e 6e 65 74 } //01 00  Lexx@baklanov.net
		$a_03_1 = {8b 38 ff 57 90 01 01 8b 45 90 01 01 8b 16 0f b6 7c 10 ff a1 90 01 04 e8 90 01 04 ba 90 01 04 2b d0 52 a1 90 01 04 e8 90 01 04 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 45 90 01 01 e8 90 01 04 8b 55 90 1b 07 b8 90 01 04 e8 90 01 04 ff 06 ff 4d 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}