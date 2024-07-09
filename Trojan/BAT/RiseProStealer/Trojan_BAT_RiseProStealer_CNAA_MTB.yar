
rule Trojan_BAT_RiseProStealer_CNAA_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.CNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 25 11 04 6f ?? ?? 00 0a 00 25 17 28 ?? ?? 00 06 00 25 18 28 ?? ?? 00 06 00 25 07 6f ?? ?? 00 0a 00 13 08 } //2
		$a_03_1 = {0a 13 09 11 09 09 16 09 8e 69 28 ?? ?? 00 06 13 06 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}