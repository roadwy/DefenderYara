
rule Trojan_BAT_Seraph_KAE_MTB{
	meta:
		description = "Trojan:BAT/Seraph.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 91 7e 90 01 02 00 04 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}