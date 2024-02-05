
rule Trojan_BAT_DLAgent_RDA_MTB{
	meta:
		description = "Trojan:BAT/DLAgent.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 16 00 00 0a 25 07 6f 17 00 00 0a 6f 18 00 00 0a 26 } //00 00 
	condition:
		any of ($a_*)
 
}