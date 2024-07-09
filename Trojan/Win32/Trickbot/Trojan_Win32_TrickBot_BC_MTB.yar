
rule Trojan_Win32_TrickBot_BC_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f be 04 2f 8a d3 8a c8 f6 d2 f6 d1 0a d1 0a d8 22 d3 88 17 83 c7 01 83 6c 24 ?? 01 0f 85 } //1
		$a_02_1 = {83 c0 01 99 b9 ?? ?? ?? ?? f7 ?? 8b 4c 24 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b f2 0f b6 04 0e 03 c3 99 bb ?? ?? ?? ?? f7 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}