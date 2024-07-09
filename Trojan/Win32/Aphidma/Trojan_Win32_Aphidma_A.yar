
rule Trojan_Win32_Aphidma_A{
	meta:
		description = "Trojan:Win32/Aphidma.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 68 f5 1f 00 00 8d 85 a7 de ff ff 50 8b 45 f8 50 e8 ?? ?? ff ff 89 45 ec 83 7d ec 00 74 } //2
		$a_02_1 = {66 ba bb 01 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 83 f8 ff 75 34 66 ba bb 01 } //1
		$a_02_2 = {66 ba 50 00 b8 ?? ?? 40 00 e8 ?? ?? ff ff 83 f8 ff 75 34 66 ba 50 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}