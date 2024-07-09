
rule Trojan_BAT_Redline_GZF_MTB{
	meta:
		description = "Trojan:BAT/Redline.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 03 16 11 03 8e 69 7e ?? ?? ?? 04 28 ?? ?? ?? 06 13 07 20 00 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}