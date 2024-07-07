
rule Trojan_BAT_Asyncrat_VN_MTB{
	meta:
		description = "Trojan:BAT/Asyncrat.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 02 07 91 11 90 01 01 61 09 06 91 61 d2 9c 06 03 6f 90 01 03 0a 17 59 fe 90 01 01 13 90 01 01 11 90 01 01 2c 90 01 01 16 0a 2b 90 01 01 06 17 58 0a 07 17 58 0b 07 02 8e 69 17 59 fe 90 01 01 16 fe 90 01 01 13 90 01 01 11 90 01 01 2d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}