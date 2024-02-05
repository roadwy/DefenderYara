
rule Trojan_BAT_Remcos_NEE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 18 02 72 01 00 00 70 28 04 00 00 06 0c 08 16 08 8e 69 28 03 00 00 0a 2b 07 28 04 00 00 0a 2b e1 } //00 00 
	condition:
		any of ($a_*)
 
}