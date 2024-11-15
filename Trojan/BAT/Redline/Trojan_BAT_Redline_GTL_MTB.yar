
rule Trojan_BAT_Redline_GTL_MTB{
	meta:
		description = "Trojan:BAT/Redline.GTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 17 58 20 ff 00 00 00 5f 13 0a 11 09 11 07 11 0a 95 58 20 ff 00 00 00 5f 13 09 02 11 07 11 0a 8f 52 00 00 01 11 07 11 09 8f 52 00 00 01 28 ?? ?? ?? 06 00 11 07 11 0a 95 11 07 11 09 95 58 20 ff 00 00 00 5f 13 10 11 06 11 08 11 04 11 08 91 11 07 11 10 95 61 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 00 11 08 6e 11 06 8e 69 6a fe 04 13 11 11 11 2d 8b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}