
rule Trojan_Win32_Zbot_SIBE19_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBE19!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {31 ed ba 00 00 00 00 01 fa b8 ?? ?? ?? ?? 01 f8 89 c7 89 44 24 ?? be ?? ?? ?? ?? 01 c6 80 38 ?? 75 ?? 8a 0a 88 08 42 81 fd ?? ?? ?? ?? 7d ?? 8a 0a c0 e1 ?? 08 08 42 45 40 39 c6 75 } //1
		$a_02_1 = {5a 31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 ?? 75 ?? 31 c9 83 ea ?? 47 39 f8 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}