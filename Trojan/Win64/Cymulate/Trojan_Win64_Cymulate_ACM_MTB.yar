
rule Trojan_Win64_Cymulate_ACM_MTB{
	meta:
		description = "Trojan:Win64/Cymulate.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 89 74 24 44 33 d2 41 b8 00 10 00 00 48 8d 4c 24 60 e8 90 01 04 48 8d 54 24 44 48 8b cd ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}