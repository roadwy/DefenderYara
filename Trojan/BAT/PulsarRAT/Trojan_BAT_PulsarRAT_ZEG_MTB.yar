
rule Trojan_BAT_PulsarRAT_ZEG_MTB{
	meta:
		description = "Trojan:BAT/PulsarRAT.ZEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 16 13 06 2b 18 08 11 06 8f ?? 00 00 01 25 47 20 88 00 00 00 61 d2 52 11 06 17 58 13 06 11 06 08 8e 69 32 e1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}