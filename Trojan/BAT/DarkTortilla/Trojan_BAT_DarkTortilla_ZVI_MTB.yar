
rule Trojan_BAT_DarkTortilla_ZVI_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 1e 5d 16 fe 01 13 05 11 05 2c 12 07 11 04 02 11 04 91 20 d1 00 00 00 61 b4 9c 00 2b 0a 00 07 11 04 02 11 04 91 9c 00 11 04 17 d6 13 04 11 04 09 31 cc 07 0a 2b 00 06 2a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}