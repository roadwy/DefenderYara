
rule Trojan_Win32_Redline_UN_MTB{
	meta:
		description = "Trojan:Win32/Redline.UN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 03 4d 08 0f b6 11 33 d0 8b 45 fc 03 45 08 88 10 8b e5 5d c3 } //10
		$a_03_1 = {7a 08 e3 2c c7 45 ?? 3e 75 03 10 c7 45 ?? d4 44 89 40 c7 45 ?? bd 6a 3f 79 c7 85 ?? ?? ?? ?? 22 0b 95 10 c7 85 ?? ?? ?? ?? 7a 62 23 1f ff 15 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}