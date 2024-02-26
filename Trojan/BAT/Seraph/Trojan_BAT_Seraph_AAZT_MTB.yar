
rule Trojan_BAT_Seraph_AAZT_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {02 50 08 91 0d 02 50 08 02 50 06 08 59 17 59 91 9c 02 50 06 08 59 17 59 09 9c 08 17 58 0c 08 07 32 de } //00 00 
	condition:
		any of ($a_*)
 
}