
rule Trojan_BAT_StealerC_SPQN_MTB{
	meta:
		description = "Trojan:BAT/StealerC.SPQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 05 16 16 6f ?? ?? ?? 06 16 31 01 2a 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 11 07 17 58 13 07 11 07 1b 32 cb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}