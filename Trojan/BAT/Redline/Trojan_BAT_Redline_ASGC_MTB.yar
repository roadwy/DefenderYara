
rule Trojan_BAT_Redline_ASGC_MTB{
	meta:
		description = "Trojan:BAT/Redline.ASGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 00 11 02 91 11 00 11 03 91 58 20 00 01 00 00 5d } //1
		$a_01_1 = {11 03 11 00 11 02 91 58 20 00 01 00 00 5d 13 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}