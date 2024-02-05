
rule Ransom_Win32_Stealbit_PA_MTB{
	meta:
		description = "Ransom:Win32/Stealbit.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 81 ec 90 02 04 f6 40 68 70 56 74 90 01 01 eb 90 00 } //01 00 
		$a_03_1 = {33 c9 8b c1 83 e0 0f 8a 80 90 01 04 30 81 90 01 04 41 83 f9 7c 72 90 01 01 e8 90 01 04 e8 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}