
rule Backdoor_Win32_Delf_ZSU{
	meta:
		description = "Backdoor:Win32/Delf.ZSU,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 04 00 "
		
	strings :
		$a_03_0 = {75 2c c7 05 90 01 02 40 00 9f 86 01 00 bb 65 00 00 00 be 90 01 02 40 00 8b 06 85 c0 74 05 e8 90 01 02 ff ff 83 c6 04 4b 75 ef 6a 00 90 00 } //02 00 
		$a_02_1 = {50 69 6e 67 90 02 10 43 68 61 74 90 02 10 43 6c 6f 73 65 90 02 20 43 68 61 6e 67 65 4e 61 6d 65 7c 90 00 } //02 00 
		$a_02_2 = {25 43 4f 4d 50 55 54 45 52 4e 41 4d 45 25 90 02 10 25 4f 50 45 52 41 54 49 4e 47 53 59 53 54 45 4d 25 90 02 10 25 43 4f 55 4e 54 52 59 25 90 00 } //02 00 
		$a_02_3 = {34 2e 30 2e 90 02 10 7c 4f 6e 43 6f 6e 6e 65 63 74 7c 90 02 10 52 75 6e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 7c 90 00 } //02 00 
		$a_00_4 = {73 65 72 76 65 72 2e 65 78 65 00 53 65 6e 64 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}