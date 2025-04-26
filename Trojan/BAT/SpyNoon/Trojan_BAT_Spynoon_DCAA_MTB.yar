
rule Trojan_BAT_Spynoon_DCAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.DCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 19 5d 3a ?? 00 00 00 72 ?? ?? 00 70 12 03 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 09 17 58 0d 09 02 31 da } //2
		$a_03_1 = {17 13 05 38 ?? 00 00 00 11 04 11 05 58 13 04 11 05 17 58 13 05 11 05 02 31 ee } //2
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}