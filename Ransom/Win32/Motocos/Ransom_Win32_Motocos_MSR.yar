
rule Ransom_Win32_Motocos_MSR{
	meta:
		description = "Ransom:Win32/Motocos!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 3b 00 } //01 00 
		$a_01_1 = {77 00 6d 00 69 00 63 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 3b 00 } //01 00 
		$a_01_2 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 20 00 2f 00 73 00 65 00 74 00 20 00 7b 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 7d 00 20 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 20 00 6e 00 6f 00 3b 00 } //01 00 
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 20 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 61 00 64 00 61 00 70 00 74 00 65 00 72 00 73 00 } //02 00 
		$a_01_4 = {4d 00 6f 00 74 00 6f 00 63 00 6f 00 73 00 5f 00 52 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //02 00 
		$a_01_5 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 5f 00 52 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //02 00 
		$a_01_6 = {4d 00 6f 00 74 00 6f 00 63 00 6f 00 73 00 5f 00 62 00 6f 00 74 00 } //01 00 
		$a_01_7 = {45 6e 63 72 79 70 74 4c 6f 63 6b 46 69 6c 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}