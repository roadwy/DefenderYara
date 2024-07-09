
rule Trojan_Win32_Injuke_MBCP_MTB{
	meta:
		description = "Trojan:Win32/Injuke.MBCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 88 45 d3 0f b6 4d d3 51 8d 4d e4 e8 ?? ?? ?? ?? 0f b6 10 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9 } //1
		$a_01_1 = {61 7a 70 6a 70 75 65 64 68 65 6a 64 6f 6a 79 75 7a 73 65 67 74 76 79 78 72 6f 64 63 66 67 78 70 69 7a } //1 azpjpuedhejdojyuzsegtvyxrodcfgxpiz
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}