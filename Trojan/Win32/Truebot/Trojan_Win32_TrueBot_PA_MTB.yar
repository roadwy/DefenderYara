
rule Trojan_Win32_TrueBot_PA_MTB{
	meta:
		description = "Trojan:Win32/TrueBot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 30 38 78 2d 25 30 38 78 2e 70 73 31 } //1 %08x-%08x.ps1
		$a_01_1 = {6e 3d 25 73 26 6f 3d 25 73 26 61 3d 25 64 26 75 3d 25 73 26 70 3d 25 73 26 64 3d 25 73 } //1 n=%s&o=%s&a=%d&u=%s&p=%s&d=%s
		$a_03_2 = {33 c9 8b d9 8b 4d 90 01 01 0f b6 d0 2a cb 8b 45 90 01 01 8b f2 88 0d 90 01 04 8b cf d3 e6 33 f2 0b 35 90 01 04 03 c6 a3 90 01 04 e8 90 00 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3) >=5
 
}