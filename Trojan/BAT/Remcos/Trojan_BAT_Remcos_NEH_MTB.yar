
rule Trojan_BAT_Remcos_NEH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 06 07 73 0d 01 00 06 a2 06 07 9a 03 07 a3 22 00 00 02 6f 04 01 00 06 00 06 07 9a 02 6f 06 01 00 06 } //01 00 
		$a_01_1 = {52 53 35 35 51 37 34 44 37 48 37 47 48 } //00 00  RS55Q74D7H7GH
	condition:
		any of ($a_*)
 
}