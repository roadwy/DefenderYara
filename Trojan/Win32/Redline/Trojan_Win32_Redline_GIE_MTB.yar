
rule Trojan_Win32_Redline_GIE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 11 88 55 db 0f b6 4d db 8b 45 dc 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d e3 8b 45 08 03 45 dc 8a 08 88 4d da 8a 55 da 88 55 d9 0f b6 45 e3 8b 4d 08 03 4d dc 0f b6 11 03 d0 8b 45 08 03 45 dc 88 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}