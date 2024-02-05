
rule Backdoor_WinNT_Farfli_E_sys{
	meta:
		description = "Backdoor:WinNT/Farfli.E!sys,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 08 00 "
		
	strings :
		$a_03_0 = {38 08 74 11 3b 4c 24 90 01 01 7d 0b 80 04 01 90 01 01 41 80 3c 01 00 75 ef 90 02 01 c2 08 00 90 00 } //05 00 
		$a_01_1 = {3d 24 0c 0b 83 74 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_WinNT_Farfli_E_sys_2{
	meta:
		description = "Backdoor:WinNT/Farfli.E!sys,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 8b 10 a1 90 01 04 39 50 08 77 07 bf 0d 00 00 c0 eb 3e 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 03 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 90 00 } //01 00 
		$a_00_1 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00 
		$a_02_2 = {83 c7 fd eb 90 01 01 83 3d 90 01 02 01 00 90 01 01 76 90 01 01 ff 15 90 01 02 01 00 a1 90 01 02 01 00 8b 38 83 90 02 20 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 90 01 01 e4 8b 00 89 04 90 01 01 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}