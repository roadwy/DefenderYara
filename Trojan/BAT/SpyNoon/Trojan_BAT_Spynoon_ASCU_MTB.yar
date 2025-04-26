
rule Trojan_BAT_Spynoon_ASCU_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ASCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 8e 69 17 da 13 0e 16 13 0f 2b 1b 11 06 11 05 11 0f 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 0f 17 d6 13 0f 11 0f 11 0e 31 } //1
		$a_01_1 = {44 00 4a 00 4b 00 47 00 59 00 53 00 4a 00 48 00 44 00 48 00 4a 00 20 00 4b 00 44 00 47 00 4a 00 4b 00 48 00 53 00 44 00 47 00 4b 00 4a 00 48 00 53 00 44 00 47 00 } //1 DJKGYSJHDHJ KDGJKHSDGKJHSDG
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}