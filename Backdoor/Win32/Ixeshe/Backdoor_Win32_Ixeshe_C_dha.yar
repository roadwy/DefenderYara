
rule Backdoor_Win32_Ixeshe_C_dha{
	meta:
		description = "Backdoor:Win32/Ixeshe.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 44 24 1c c7 44 24 1c 00 00 00 00 50 68 7f 66 04 40 55 e8 90 01 04 85 c0 75 24 8b 4c 24 18 8b 44 24 1c 81 e1 ff ff 00 00 3b c1 73 0b 6a 32 90 00 } //01 00 
		$a_01_1 = {8d 54 24 1c c7 44 24 14 01 00 00 00 33 f6 8d 44 24 14 50 68 c7 00 00 00 52 55 ff d7 8b 44 24 14 03 f0 81 fe d0 07 00 00 8d 54 04 1c } //00 00 
	condition:
		any of ($a_*)
 
}