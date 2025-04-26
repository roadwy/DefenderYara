
rule Trojan_BAT_Redline_GTZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {1b 11 06 8f ?? ?? ?? 01 25 47 09 11 06 58 1f 11 5a 20 00 01 00 00 5d d2 61 d2 52 09 1f 1f 5a 08 75 ?? ?? ?? 1b 11 06 91 58 20 00 01 00 00 5d 0d 11 06 17 58 13 06 11 06 08 75 ?? ?? ?? 1b 8e 69 32 b9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}