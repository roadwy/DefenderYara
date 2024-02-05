
rule Trojan_Win32_Gh0stLoader_A_dha{
	meta:
		description = "Trojan:Win32/Gh0stLoader.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 8d 9c 39 } //01 00 
		$a_01_1 = {42 09 9e 5f } //01 00 
		$a_01_2 = {e2 9a 5a f5 } //01 00 
		$a_01_3 = {1b c2 10 3b } //01 00 
		$a_01_4 = {71 a7 e8 fe } //01 00 
		$a_01_5 = {81 8f f0 4e } //00 00 
	condition:
		any of ($a_*)
 
}