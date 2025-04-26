
rule Trojan_BAT_Heracles_ABRW_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ABRW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 05 1a 8d ?? 00 00 01 25 16 11 04 a2 25 17 7e ?? 00 00 0a a2 25 18 07 a2 25 19 17 8c ?? 00 00 01 a2 13 06 11 05 08 6f ?? 00 00 0a 09 20 00 01 00 00 14 14 11 06 } //4
		$a_01_1 = {4a 00 48 00 68 00 36 00 36 00 33 00 36 00 33 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 JHh66363.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}