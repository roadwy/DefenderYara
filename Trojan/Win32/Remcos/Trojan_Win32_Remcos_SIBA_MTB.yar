
rule Trojan_Win32_Remcos_SIBA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 68 39 4f 42 } //01 00  Uh9OB
		$a_00_1 = {55 68 58 56 42 } //01 00  UhXVB
		$a_00_2 = {55 68 32 5a 42 } //01 00  Uh2ZB
		$a_03_3 = {ba 01 00 00 00 a1 90 01 04 8b 38 ff 57 90 01 01 8b 45 90 01 01 8b 16 0f b6 7c 10 ff b8 90 01 04 e8 90 01 04 ba 00 01 00 00 2b d0 52 b8 90 01 04 e8 90 01 04 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 45 90 01 01 e8 90 01 04 8b 55 90 1b 07 b8 90 01 04 e8 90 01 04 ff 06 ff 4d 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}