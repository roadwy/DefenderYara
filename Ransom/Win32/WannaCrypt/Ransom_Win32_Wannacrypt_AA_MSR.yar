
rule Ransom_Win32_Wannacrypt_AA_MSR{
	meta:
		description = "Ransom:Win32/Wannacrypt.AA!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 20 53 6e 63 2e 65 78 65 } //01 00 
		$a_01_1 = {57 43 72 79 5c 57 43 72 79 5c 42 61 6e 6e 65 72 5c 57 70 66 41 70 70 31 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 52 61 6e 73 6f 6d 77 61 72 65 20 53 6e 63 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}