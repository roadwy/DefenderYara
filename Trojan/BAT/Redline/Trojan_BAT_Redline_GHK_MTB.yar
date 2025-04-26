
rule Trojan_BAT_Redline_GHK_MTB{
	meta:
		description = "Trojan:BAT/Redline.GHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 7e ?? ?? ?? ?? 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 1e 58 1d 59 03 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 08 17 58 16 2c 3f 26 08 6a 03 8e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}