
rule Trojan_BAT_Redline_GBN_MTB{
	meta:
		description = "Trojan:BAT/Redline.GBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 02 09 91 07 09 04 5d 93 28 ?? ?? ?? 06 d2 9c 00 09 17 58 0d 09 06 fe 04 13 04 11 04 2d df } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}