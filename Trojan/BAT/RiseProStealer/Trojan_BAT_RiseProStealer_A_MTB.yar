
rule Trojan_BAT_RiseProStealer_A_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 94 19 18 8d 90 01 01 00 00 01 13 93 11 93 16 14 a2 90 00 } //2
		$a_01_1 = {11 94 17 05 50 a2 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}