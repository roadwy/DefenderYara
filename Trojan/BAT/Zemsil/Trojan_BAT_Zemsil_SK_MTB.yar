
rule Trojan_BAT_Zemsil_SK_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 22 11 1a 11 1c 58 11 1b 11 1d 58 6f ?? ?? ?? 0a 13 5f 12 5f 28 ?? ?? ?? 0a 13 24 11 1f 11 1e 11 24 9c 11 1e 17 58 13 1e 11 1d 17 58 13 1d 11 1d 17 fe 04 13 25 11 25 2d c6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}