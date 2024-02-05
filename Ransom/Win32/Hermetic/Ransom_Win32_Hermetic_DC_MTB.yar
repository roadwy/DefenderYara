
rule Ransom_Win32_Hermetic_DC_MTB{
	meta:
		description = "Ransom:Win32/Hermetic.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 13 6d 4e c6 41 8b 43 04 6a 1a 59 81 c2 39 30 00 00 89 13 23 c2 33 d2 f7 f1 } //00 00 
	condition:
		any of ($a_*)
 
}