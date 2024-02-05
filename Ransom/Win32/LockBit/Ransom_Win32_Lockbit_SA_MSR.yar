
rule Ransom_Win32_Lockbit_SA_MSR{
	meta:
		description = "Ransom:Win32/Lockbit.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 75 74 64 6f 77 6e 42 6c 6f 63 6b 52 65 61 73 6f 6e 43 72 65 61 74 65 } //02 00 
		$a_01_1 = {4c 6f 63 6b 42 69 74 20 52 61 6e 73 6f 6d } //02 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 6c 6f 63 6b 62 69 74 6b 73 32 74 76 6e 6d 77 6b 2e 6f 6e 69 6f 6e } //01 00 
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}