
rule Trojan_Win32_Chadivendo_STB{
	meta:
		description = "Trojan:Win32/Chadivendo.STB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 0c 3a 8a c1 c0 e1 02 c0 f8 06 0a c1 88 04 3a 42 3b d6 7c eb } //01 00 
		$a_03_1 = {8b c3 99 f7 fe 8a 04 3a 30 90 02 05 43 81 fb 90 01 04 7c 90 00 } //01 00 
		$a_03_2 = {8d 45 f0 c7 45 f0 90 01 04 50 8b 45 fc c7 45 f4 90 01 04 ff d0 90 00 } //01 00 
		$a_00_3 = {80 4f 00 00 00 5f ff ff ff ff 47 6c 6f 62 61 6c 5c } //00 00 
		$a_00_4 = {5d 04 00 } //00 8a 
	condition:
		any of ($a_*)
 
}