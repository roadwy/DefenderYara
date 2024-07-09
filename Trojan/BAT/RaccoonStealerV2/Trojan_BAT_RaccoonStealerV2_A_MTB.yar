
rule Trojan_BAT_RaccoonStealerV2_A_MTB{
	meta:
		description = "Trojan:BAT/RaccoonStealerV2.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 70 18 17 8d ?? 00 00 01 25 16 72 ?? ?? 00 70 a2 28 ?? ?? 00 0a 74 ?? 00 00 1b 13 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}