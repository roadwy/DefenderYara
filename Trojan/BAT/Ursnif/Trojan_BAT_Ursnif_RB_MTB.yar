
rule Trojan_BAT_Ursnif_RB_MTB{
	meta:
		description = "Trojan:BAT/Ursnif.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 26 00 03 74 90 01 04 72 90 01 04 20 90 01 04 14 14 14 6f 90 01 04 2c 02 de 0e de 03 26 de 00 06 17 58 0a 06 1f 0a 32 d5 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}