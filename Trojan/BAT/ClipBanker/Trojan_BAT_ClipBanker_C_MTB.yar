
rule Trojan_BAT_ClipBanker_C_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 b5 02 3c 09 07 00 00 00 00 00 00 00 00 00 00 01 00 00 00 7a 00 00 00 26 00 00 00 c6 } //01 00 
		$a_01_1 = {2e 00 4e 00 45 00 54 00 20 00 52 00 65 00 61 00 63 00 74 00 6f 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}