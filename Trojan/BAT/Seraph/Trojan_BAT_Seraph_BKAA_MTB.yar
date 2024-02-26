
rule Trojan_BAT_Seraph_BKAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.BKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 0e 02 06 02 06 91 1f 7b 61 d2 9c 06 17 58 0a 06 02 8e 69 32 ec } //00 00 
	condition:
		any of ($a_*)
 
}