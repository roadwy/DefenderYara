
rule VirTool_Win32_Obfuscator_RJ{
	meta:
		description = "VirTool:Win32/Obfuscator.RJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 08 00 00 "
		
	strings :
		$a_01_0 = {60 0f 00 c1 e3 0d 0f 00 c0 2b c8 } //1
		$a_01_1 = {59 8b dd ac 32 c3 aa e2 d0 5d } //1
		$a_01_2 = {f3 a4 5e 56 33 c9 66 8b 4e 06 81 c6 f8 00 00 00 } //1
		$a_01_3 = {e2 df 59 8b dd ac 32 c3 aa } //1
		$a_01_4 = {83 c6 28 e2 e5 5e 8b 46 28 03 45 fc ff e0 } //1
		$a_01_5 = {e2 d5 59 8b 5d fc ac 32 c3 aa } //1
		$a_03_6 = {83 c6 28 e2 e5 5e ff 75 fc e8 90 01 02 00 00 8b 46 28 03 45 fc ff d0 90 00 } //1
		$a_01_7 = {ac 32 c3 aa f7 c1 01 00 00 00 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1) >=2
 
}