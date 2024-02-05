
rule Trojan_BAT_ClipBanker_AG_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 fd 02 3c 09 0b 00 00 00 f8 00 30 00 02 00 00 01 00 00 00 4f 00 00 00 3b 00 00 00 92 00 00 00 90 } //01 00 
		$a_01_1 = {43 6f 6e 74 61 69 6e 73 54 65 78 74 } //01 00 
		$a_01_2 = {49 73 4d 61 74 63 68 } //00 00 
	condition:
		any of ($a_*)
 
}