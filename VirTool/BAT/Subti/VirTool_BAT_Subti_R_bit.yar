
rule VirTool_BAT_Subti_R_bit{
	meta:
		description = "VirTool:BAT/Subti.R!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_02_0 = {00 28 1d 00 00 0a 6a 0a 20 ?? ?? ?? 00 28 04 00 00 0a 00 28 1d 00 00 0a 6a 0b 07 06 59 20 90 1b 00 00 } //1
		$a_01_1 = {54 00 68 00 65 00 20 00 57 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00 20 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 41 00 6e 00 61 00 6c 00 79 00 7a 00 65 00 72 00 } //1 The Wireshark Network Analyzer
		$a_01_2 = {53 00 62 00 69 00 65 00 44 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 } //1 SbieDll.dll
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_4 = {49 00 6e 00 6a 00 00 0d 69 00 74 00 73 00 65 00 6c 00 66 00 } //1 Injഀitself
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}