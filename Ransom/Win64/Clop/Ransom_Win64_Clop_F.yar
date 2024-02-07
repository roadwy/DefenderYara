
rule Ransom_Win64_Clop_F{
	meta:
		description = "Ransom:Win64/Clop.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 00 65 00 6d 00 70 00 2e 00 6f 00 63 00 78 00 } //01 00  temp.ocx
		$a_01_1 = {45 00 4e 00 44 00 4f 00 45 00 46 00 45 00 4e 00 44 00 31 00 32 00 33 00 } //00 00  ENDOEFEND123
	condition:
		any of ($a_*)
 
}