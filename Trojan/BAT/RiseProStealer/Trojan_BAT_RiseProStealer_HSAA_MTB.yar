
rule Trojan_BAT_RiseProStealer_HSAA_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.HSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 02 11 15 7b ?? 00 00 04 91 58 20 00 01 00 00 5d 13 01 } //2
		$a_03_1 = {05 11 0c 8f ?? 00 00 01 25 71 ?? 00 00 01 11 02 11 10 91 61 d2 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}