
rule Trojan_BAT_Injuke_SPDP_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SPDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 37 00 00 00 11 03 11 01 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 16 11 01 8e 69 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}