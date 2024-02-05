
rule Trojan_BAT_Remcos_RDG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 37 64 66 34 30 62 36 2d 39 30 33 35 2d 34 63 37 61 2d 38 34 33 37 2d 39 62 61 32 64 39 63 35 34 62 38 31 } //01 00 
		$a_01_1 = {4a 68 48 68 37 32 36 } //01 00 
		$a_81_2 = {52 49 41 4d } //01 00 
		$a_81_3 = {4d 49 41 58 53 } //00 00 
	condition:
		any of ($a_*)
 
}