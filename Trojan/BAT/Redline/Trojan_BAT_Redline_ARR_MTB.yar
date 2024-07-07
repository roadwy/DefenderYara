
rule Trojan_BAT_Redline_ARR_MTB{
	meta:
		description = "Trojan:BAT/Redline.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {9a 0d 00 09 6f 90 01 03 0a 72 61 00 00 70 6f 90 01 03 0a 16 fe 01 13 90 00 } //1
		$a_03_1 = {2d 1c 00 12 02 08 8e 69 17 58 28 90 01 03 2b 00 08 08 8e 69 17 59 09 6f 90 01 03 0a a2 00 00 11 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}