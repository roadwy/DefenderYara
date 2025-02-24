
rule Trojan_Win32_Runner_CCJT_MTB{
	meta:
		description = "Trojan:Win32/Runner.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 b2 01 f8 0f be 08 8d 58 01 b8 ?? ?? ?? ?? 85 c9 74 ?? 89 34 24 8d b4 26 00 00 00 00 66 90 90 89 c6 83 c3 01 c1 e6 05 01 c6 8d 04 0e 0f be 4b ?? 85 c9 75 } //2
		$a_03_1 = {83 ec 14 85 c0 75 ?? c7 04 24 ?? ?? ?? ?? ff d3 52 85 c0 74 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}