
rule Trojan_Win32_Gepys_VDK_MTB{
	meta:
		description = "Trojan:Win32/Gepys.VDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {89 55 e4 99 f7 7d e4 01 c1 8b 45 ec 03 4d 08 99 f7 7d e0 03 45 08 4f 8a 10 88 55 ec 8a 11 e9 } //2
		$a_00_1 = {8a 28 00 dd 88 df 8a 0a d2 e7 88 f9 8a 3a 00 cf 88 38 0f b6 c5 88 d9 d3 f8 88 02 } //2
		$a_02_2 = {ba 3d 24 00 00 e9 90 09 0b 00 e8 ?? ?? ?? ?? 59 e9 } //1
		$a_02_3 = {31 34 81 e9 90 09 07 00 3b c2 e9 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}