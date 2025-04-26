
rule VirTool_Win32_Obfuscator_US{
	meta:
		description = "VirTool:Win32/Obfuscator.US,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {ff 74 18 78 58 } //1
		$a_01_1 = {74 8f fc 03 f3 52 } //1
		$a_01_2 = {ff 74 8f fc 5e } //1
		$a_01_3 = {58 0f b7 7c 4a fe 03 1c b8 } //1
		$a_01_4 = {33 55 fc 33 ca 68 00 00 00 00 8f 43 0c } //1
		$a_03_5 = {74 13 49 75 ?? 58 c1 e0 ?? c1 e0 ?? d1 e0 5e } //1
		$a_03_6 = {0c 20 c1 c2 ?? c1 c2 ?? c1 ca ?? c1 c2 ?? 32 d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=4
 
}