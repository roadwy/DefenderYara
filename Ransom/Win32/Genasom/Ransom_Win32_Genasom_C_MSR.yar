
rule Ransom_Win32_Genasom_C_MSR{
	meta:
		description = "Ransom:Win32/Genasom.C!MSR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 61 63 6b 70 6f 74 40 6a 61 62 62 65 72 2e 63 64 20 28 } //01 00 
		$a_01_1 = {4b 61 73 70 65 72 73 6b 79 20 45 76 65 6e 74 20 4c 6f 67 } //01 00 
		$a_01_2 = {44 6f 63 74 6f 72 20 57 65 62 } //01 00 
		$a_01_3 = {53 79 6d 61 6e 74 65 63 20 45 6e 64 70 6f 69 6e 74 20 50 72 6f 74 65 63 74 69 6f 6e 20 43 6c 69 65 6e 74 } //01 00 
		$a_01_4 = {49 4e 53 54 52 55 43 54 49 4f 4e 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}