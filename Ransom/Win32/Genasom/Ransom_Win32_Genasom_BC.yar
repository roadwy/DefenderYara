
rule Ransom_Win32_Genasom_BC{
	meta:
		description = "Ransom:Win32/Genasom.BC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 22 00 22 20 3e 3e 20 4e 55 4c 00 74 65 6d 70 73 79 73 2e 65 78 65 } //01 00 
		$a_01_1 = {e8 f2 e5 20 e2 20 53 4d 53 20 ed e0 20 f3 ea e0 } //01 00 
		$a_01_2 = {70 6f 72 6e 68 75 62 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}