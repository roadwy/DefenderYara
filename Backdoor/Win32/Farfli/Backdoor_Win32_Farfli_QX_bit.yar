
rule Backdoor_Win32_Farfli_QX_bit{
	meta:
		description = "Backdoor:Win32/Farfli.QX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 44 2f 01 8a 14 1e 47 32 d0 6a 00 88 14 1e ff 15 90 01 04 8b c6 b9 05 00 00 00 99 f7 f9 85 d2 75 02 33 ff 8b 44 24 18 46 3b f0 7c d2 90 00 } //01 00 
		$a_01_1 = {66 3d 7e 00 75 02 33 c0 8a 19 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 da 40 88 19 41 4e 75 e1 } //00 00 
	condition:
		any of ($a_*)
 
}