
rule Trojan_BAT_RiseProStealer_SK_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 29 11 0a 6f 03 00 00 0a 13 26 11 0b 11 26 11 14 59 61 13 0b 11 14 1f 0a 28 6c 00 00 06 11 0b 58 17 28 6c 00 00 06 63 59 13 14 11 0a 28 af 01 00 06 2d ce de 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}