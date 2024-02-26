
rule Trojan_BAT_Marsilia_PTCU_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.PTCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 16 11 05 6f 45 00 00 0a 07 11 04 16 11 04 8e 69 6f 3e 00 00 0a 13 05 11 05 16 30 db } //00 00 
	condition:
		any of ($a_*)
 
}