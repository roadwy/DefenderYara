
rule Trojan_BAT_RedLineStealer_SPDP_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.SPDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 7e 01 00 00 04 6f ?? ?? ?? 06 8e 69 20 ?? ?? ?? 00 1f 40 28 ?? ?? ?? 06 0a 16 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}