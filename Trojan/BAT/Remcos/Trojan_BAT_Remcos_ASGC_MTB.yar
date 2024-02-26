
rule Trojan_BAT_Remcos_ASGC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ASGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 0c 08 11 0a 91 61 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 11 } //01 00 
		$a_01_1 = {07 11 09 91 13 0c 20 00 01 00 00 13 0d } //00 00 
	condition:
		any of ($a_*)
 
}