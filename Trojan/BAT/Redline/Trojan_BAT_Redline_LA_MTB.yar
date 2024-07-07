
rule Trojan_BAT_Redline_LA_MTB{
	meta:
		description = "Trojan:BAT/Redline.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 8f 85 90 01 03 25 4b 03 06 95 61 54 06 17 59 0a 06 16 90 00 } //5
		$a_03_1 = {06 6e 17 07 1f 1f 5f 62 6a 5f 39 17 90 01 03 02 16 8f 85 90 01 03 25 4b 90 01 05 1d 07 59 1f 1f 5f 64 61 54 07 17 59 0b 07 16 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}