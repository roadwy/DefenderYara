
rule Trojan_BAT_Seraph_SPFV_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 02 07 6f 7e 00 00 0a 03 07 6f 7e 00 00 0a 61 60 0a 07 17 58 0b } //00 00 
	condition:
		any of ($a_*)
 
}