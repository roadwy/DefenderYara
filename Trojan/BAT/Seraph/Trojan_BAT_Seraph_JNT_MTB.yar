
rule Trojan_BAT_Seraph_JNT_MTB{
	meta:
		description = "Trojan:BAT/Seraph.JNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 06 7b 05 00 00 04 09 9e 02 03 06 7b 05 00 00 04 17 59 28 06 00 00 06 02 06 7b 05 00 00 04 17 58 04 28 06 00 00 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}