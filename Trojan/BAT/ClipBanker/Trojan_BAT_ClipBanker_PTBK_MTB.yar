
rule Trojan_BAT_ClipBanker_PTBK_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PTBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 77 00 00 70 6f 1f 00 00 0a 25 72 95 00 00 70 02 72 ab 00 00 70 28 90 01 01 00 00 0a 6f 2e 00 00 0a 25 17 6f 2f 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}