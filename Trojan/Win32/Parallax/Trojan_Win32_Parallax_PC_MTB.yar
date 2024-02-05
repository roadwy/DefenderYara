
rule Trojan_Win32_Parallax_PC_MTB{
	meta:
		description = "Trojan:Win32/Parallax.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 f3 00 57 e0 05 8b 44 24 14 05 00 10 00 00 83 ec 04 54 e9 90 01 02 ff ff 90 00 } //01 00 
		$a_02_1 = {31 1f 83 c7 04 83 e9 04 e9 90 01 02 ff ff 90 00 } //01 00 
		$a_02_2 = {83 f9 00 0f 8f 90 01 02 00 00 5f bb 20 c6 e7 05 e9 90 01 02 00 00 90 00 } //01 00 
		$a_00_3 = {b9 78 00 00 00 b8 23 00 00 00 03 c8 2b c1 83 c1 75 83 c0 12 8b c0 8b c0 8b c0 8b c8 8b c8 8b c9 8b c9 a8 23 } //00 00 
	condition:
		any of ($a_*)
 
}