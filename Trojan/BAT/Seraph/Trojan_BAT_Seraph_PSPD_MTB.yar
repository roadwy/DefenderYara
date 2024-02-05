
rule Trojan_BAT_Seraph_PSPD_MTB{
	meta:
		description = "Trojan:BAT/Seraph.PSPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 30 00 00 06 28 32 00 00 06 74 42 00 00 01 28 31 00 00 06 74 04 00 00 1b 28 2e 00 00 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}