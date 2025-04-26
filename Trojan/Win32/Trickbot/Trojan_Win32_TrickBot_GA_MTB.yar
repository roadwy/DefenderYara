
rule Trojan_Win32_TrickBot_GA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 [0-0a] 8a 04 1a 30 04 31 41 3b cf 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBot_GA_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 07 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 45 ?? 83 c4 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}