
rule Trojan_BAT_Redline_CO_MTB{
	meta:
		description = "Trojan:BAT/Redline.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 1f 09 7e 6c 00 00 04 1f 29 7e 6c 00 00 04 1f 29 94 7e 6c 00 00 04 1f 0e 94 61 1f 41 5f 9e fe 02 13 06 11 06 } //5
		$a_01_1 = {58 11 08 5d 93 61 d1 6f b5 00 00 0a 26 1f 10 13 0e } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}