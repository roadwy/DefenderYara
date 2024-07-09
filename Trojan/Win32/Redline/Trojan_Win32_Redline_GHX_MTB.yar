
rule Trojan_Win32_Redline_GHX_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 d8 8a 02 88 45 d7 0f b6 4d d7 8b 45 d8 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d df 8b 45 08 03 45 d8 8a 08 88 4d d6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}