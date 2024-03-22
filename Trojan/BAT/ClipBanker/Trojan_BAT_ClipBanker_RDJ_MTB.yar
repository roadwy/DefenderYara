
rule Trojan_BAT_ClipBanker_RDJ_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 07 6f 2f 00 00 0a 17 73 30 00 00 0a 25 02 16 } //00 00 
	condition:
		any of ($a_*)
 
}