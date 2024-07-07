
rule Trojan_BAT_DarkTortilla_ATO_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ATO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 16 25 2d 55 25 2d f3 13 04 2b 1c 11 08 11 04 11 0a 11 04 11 0a 8e 69 5d 91 9e 11 09 11 04 11 04 9e 11 04 17 58 13 04 11 04 20 00 01 00 00 32 db } //1
		$a_03_1 = {11 09 09 94 13 07 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 07 9e 16 3a 90 01 03 ff 11 09 11 09 09 94 11 09 11 05 94 58 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}