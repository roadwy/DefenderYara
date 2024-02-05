
rule Ransom_Win64_Rhysida_YAP_MTB{
	meta:
		description = "Ransom:Win64/Rhysida.YAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 d3 ed 89 d9 49 d3 e0 44 89 c9 4d 21 d5 4d 09 f0 4d 21 d8 90 01 04 49 89 d0 49 d3 e8 89 d9 48 d3 e2 4d 21 d0 4c 09 ea 4d 89 c6 4c 21 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}