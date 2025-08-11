
rule Trojan_Win32_Tinba_ATI_MTB{
	meta:
		description = "Trojan:Win32/Tinba.ATI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f1 89 45 c4 8b 55 a8 81 e2 b9 02 00 00 8b 45 c8 2b c2 89 45 c8 c7 85 a8 fe ff ff e8 c5 41 00 8b 8d a8 fe ff ff 51 68 98 0f 00 00 68 78 0a 00 00 ff 15 ?? ?? ?? ?? 8b 75 b4 03 75 c8 8b 4d d8 d3 e6 } //3
		$a_03_1 = {8b 45 c4 33 d2 f7 f6 89 45 c4 ba 71 02 00 00 2b 55 d8 8b 45 c4 33 c2 89 45 c4 68 79 01 00 00 8d 8d 98 fe ff ff 51 ff 15 ?? ?? ?? ?? 8b 55 c0 8b 4d dc d3 e2 8b 4d d8 d3 e2 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}