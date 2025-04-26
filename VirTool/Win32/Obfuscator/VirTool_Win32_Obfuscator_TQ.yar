
rule VirTool_Win32_Obfuscator_TQ{
	meta:
		description = "VirTool:Win32/Obfuscator.TQ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {39 4d ec 76 12 8a 14 18 80 f2 ?? 80 c2 ?? 88 14 18 40 3b 45 ec 72 ee 8b d3 8d 45 d8 } //1
		$a_01_1 = {0f b6 94 15 bc fe ff ff c1 e0 06 03 45 bc 41 c1 e0 06 03 c7 c1 e0 06 03 c2 3b 75 10 73 25 8b 7d 0c 8b d0 c1 ea 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}