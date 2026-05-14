
rule Trojan_BAT_AMSIBypass_ARR_MTB{
	meta:
		description = "Trojan:BAT/AMSIBypass.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 06 07 8e 69 6a 28 ?? ?? ?? ?? 1f 40 12 02 28 ?? ?? ?? ?? 26 07 06 28 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}