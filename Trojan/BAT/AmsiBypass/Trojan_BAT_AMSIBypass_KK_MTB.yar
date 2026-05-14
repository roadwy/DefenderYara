
rule Trojan_BAT_AMSIBypass_KK_MTB{
	meta:
		description = "Trojan:BAT/AMSIBypass.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 9a 28 ?? ?? ?? 0a 03 5b d2 9c 08 17 58 0c 08 07 8e 69 32 e8 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}