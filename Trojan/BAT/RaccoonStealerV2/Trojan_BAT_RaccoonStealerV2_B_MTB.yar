
rule Trojan_BAT_RaccoonStealerV2_B_MTB{
	meta:
		description = "Trojan:BAT/RaccoonStealerV2.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 16 6f ?? ?? 00 0a 13 04 12 04 28 ?? ?? 00 0a 13 05 08 11 05 6f ?? ?? 00 0a 09 17 58 0d 09 07 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}