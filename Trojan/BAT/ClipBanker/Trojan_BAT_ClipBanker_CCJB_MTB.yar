
rule Trojan_BAT_ClipBanker_CCJB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.CCJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 02 00 25 20 01 00 00 00 58 fe 0e 02 00 6f ?? 00 00 0a 61 d2 6f ?? 00 00 0a fe 0c 02 00 fe 0c 00 00 6f ?? 00 00 0a 5d fe 0e 02 00 fe 0c 04 00 20 01 00 00 00 58 fe 0e 04 00 fe 0c 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}