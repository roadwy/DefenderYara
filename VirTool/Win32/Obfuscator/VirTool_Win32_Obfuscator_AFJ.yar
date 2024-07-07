
rule VirTool_Win32_Obfuscator_AFJ{
	meta:
		description = "VirTool:Win32/Obfuscator.AFJ,SIGNATURE_TYPE_PEHSTR_EXT,32 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 01 00 00 00 c3 5d 81 ed 28 24 40 00 45 bb 00 00 00 00 be 00 00 00 00 8d bb 00 41 7a 00 57 33 c9 81 f9 00 04 00 00 74 38 83 f9 00 75 21 60 bb 00 00 00 00 be 00 00 00 00 8d bb 00 41 7a 00 8d 8b 73 03 00 00 bb 00 86 42 00 03 f3 f3 a5 61 8a 07 88 07 8a 47 01 88 47 01 83 c7 04 83 c1 04 eb c0 33 c9 81 f9 00 00 f0 00 74 19 81 f9 23 00 30 00 75 0e 5e 81 ee 00 00 01 00 b8 00 00 60 00 ff e6 41 eb df 00 00 00 00 00 00 00 00 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}