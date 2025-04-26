
rule Trojan_Win32_Agent_AAE{
	meta:
		description = "Trojan:Win32/Agent.AAE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 75 08 8b 46 3c 8b 44 30 78 03 c6 8b ?? 1c 8b ?? 20 8b ?? 24 8b ?? 18 } //1
		$a_01_1 = {29 45 08 8b 45 08 c1 c8 07 89 45 08 ff 45 } //1
		$a_02_2 = {0f 84 07 00 00 00 0f 85 01 00 00 00 e8 0f b6 85 ?? ?? ff ff 83 e0 0f } //1
		$a_03_3 = {83 f8 72 75 ?? 0f be 85 ?? ?? ff ff 83 f8 03 75 2a 0f be 85 ?? ?? ff ff 83 f8 73 75 1e 0f be 85 83 ea ff ff 83 f8 01 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}