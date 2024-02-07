
rule TrojanProxy_Win32_Bunitu_O{
	meta:
		description = "TrojanProxy:Win32/Bunitu.O,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 41 07 32 fe 09 fe 41 01 fe 09 fe 49 05 c6 41 06 } //01 00 
		$a_03_1 = {83 c2 01 c1 e2 03 c1 e2 03 8d 04 02 ba 90 01 04 52 8f 00 83 28 08 90 00 } //01 00 
		$a_01_2 = {89 10 b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 } //01 00 
		$a_01_3 = {00 61 61 63 6c 66 64 3a 00 } //00 00 
		$a_00_4 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}