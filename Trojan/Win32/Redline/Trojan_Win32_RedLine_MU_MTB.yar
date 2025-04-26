
rule Trojan_Win32_RedLine_MU_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 33 d2 f7 75 14 8b 4d 08 0f be 04 11 6b c0 47 99 b9 2d 00 00 00 f7 f9 6b c0 3d 99 b9 22 00 00 00 f7 f9 6b c0 1a 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}