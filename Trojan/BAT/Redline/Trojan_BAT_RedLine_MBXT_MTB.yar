
rule Trojan_BAT_RedLine_MBXT_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 30 00 00 01 13 0a 11 09 11 0a 16 11 0a 8e 69 6f cc 00 00 0a 26 11 09 28 4e 1d 00 06 16 13 0b 14 13 0c } //3
		$a_01_1 = {74 65 6d 70 6c 61 74 65 38 33 32 63 6f 6d 70 6f 6e 65 6e 74 73 } //2 template832components
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}