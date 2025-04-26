
rule Trojan_Win32_Zbot_AAO_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AAO!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a c1 80 fa 08 72 0e 56 0f b6 f2 c1 ee 03 80 c2 f8 4e 75 fa 5e 8a ca d2 c0 c3 } //1
		$a_01_1 = {8a 06 2a 45 ff 8a 56 02 8b 4e 10 8a 5e 14 fe c8 32 d0 8a c2 32 45 fe 85 c9 74 08 84 db 0f 85 a0 00 00 00 33 c0 85 c0 74 09 32 55 fd 8a 0f ff d0 88 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}