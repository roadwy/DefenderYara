
rule Trojan_BAT_RiseProStealer_B_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 19 17 8d ?? 00 00 01 13 03 11 03 16 04 a2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}