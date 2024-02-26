
rule Trojan_BAT_Seraph_AAYT_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {06 09 91 13 04 06 09 06 07 09 59 17 59 91 9c 06 07 09 59 17 59 11 04 9c 09 17 58 0d 09 08 32 e0 } //00 00 
	condition:
		any of ($a_*)
 
}