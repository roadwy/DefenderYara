
rule TrojanDropper_Win32_Monkif_A{
	meta:
		description = "TrojanDropper:Win32/Monkif.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 7d f4 93 08 00 00 74 0c 46 81 fe e8 19 10 00 7c e4 } //01 00 
		$a_03_1 = {6a e8 53 ff 15 90 01 04 83 f8 ff 74 1f 57 8d 45 f4 50 6a 10 56 8b 35 04 20 40 00 53 ff d6 57 8d 45 f4 50 6a 08 90 00 } //01 00 
		$a_03_2 = {43 83 fb 0a 7f 28 68 d0 07 00 00 ff 15 90 01 04 e8 90 01 04 81 3d 90 01 04 00 03 00 00 74 de 81 3d 90 01 04 01 03 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}