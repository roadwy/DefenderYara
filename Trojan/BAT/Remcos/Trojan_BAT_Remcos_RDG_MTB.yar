
rule Trojan_BAT_Remcos_RDG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 37 64 66 34 30 62 36 2d 39 30 33 35 2d 34 63 37 61 2d 38 34 33 37 2d 39 62 61 32 64 39 63 35 34 62 38 31 } //01 00  f7df40b6-9035-4c7a-8437-9ba2d9c54b81
		$a_01_1 = {4a 68 48 68 37 32 36 } //01 00  JhHh726
		$a_81_2 = {52 49 41 4d } //01 00  RIAM
		$a_81_3 = {4d 49 41 58 53 } //00 00  MIAXS
	condition:
		any of ($a_*)
 
}