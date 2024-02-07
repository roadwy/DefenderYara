
rule Backdoor_Win32_Bafruz_K{
	meta:
		description = "Backdoor:Win32/Bafruz.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 84 50 8d 45 80 8b 4d fc ba 90 09 0e 00 68 90 90 1f 00 00 68 10 27 00 00 6a 01 6a 00 90 00 } //01 00 
		$a_01_1 = {73 79 73 74 65 6d 69 6e 66 6f 67 } //02 00  systeminfog
		$a_03_2 = {73 6f 66 74 5f 6c 69 73 74 00 00 00 ff ff ff ff 02 90 01 1f 30 7c 44 34 31 44 38 43 44 39 90 01 22 64 69 73 74 72 69 62 5f 73 65 72 76 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}