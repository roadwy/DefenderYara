
rule Trojan_BAT_Barys_AMAF_MTB{
	meta:
		description = "Trojan:BAT/Barys.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 1b 11 09 11 21 11 23 61 11 1a 19 58 61 11 2e 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Barys_AMAF_MTB_2{
	meta:
		description = "Trojan:BAT/Barys.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 17 d2 13 2f 11 17 1e 63 d1 13 17 11 1e 11 09 91 13 21 11 1e 11 09 11 24 11 21 61 19 11 18 58 61 11 2f 61 d2 9c 11 09 17 58 13 09 11 21 13 18 11 09 11 26 32 a4 } //5
		$a_01_1 = {11 32 11 13 11 11 11 13 91 9d 11 13 17 58 13 13 11 13 11 1b 32 ea } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}