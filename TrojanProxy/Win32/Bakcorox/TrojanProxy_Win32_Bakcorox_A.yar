
rule TrojanProxy_Win32_Bakcorox_A{
	meta:
		description = "TrojanProxy:Win32/Bakcorox.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b e8 83 c4 04 68 ff 00 00 00 8d 54 24 24 b9 bb 01 00 00 52 66 89 4d 10 } //01 00 
		$a_01_1 = {c7 44 24 18 00 00 00 00 c7 44 24 1c 00 00 00 00 80 fb 61 74 38 80 fb 73 74 15 } //01 00 
		$a_01_2 = {50 72 6f 78 79 42 6f 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}