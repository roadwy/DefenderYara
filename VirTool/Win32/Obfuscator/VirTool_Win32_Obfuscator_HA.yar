
rule VirTool_Win32_Obfuscator_HA{
	meta:
		description = "VirTool:Win32/Obfuscator.HA,SIGNATURE_TYPE_PEHSTR_EXT,09 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 10 83 c0 02 8d 80 ?? ?? ?? ?? ff e0 } //2
		$a_03_1 = {64 8b 15 18 00 00 00 41 52 [0-10] 5e 48 c7 46 14 } //1
		$a_01_2 = {c7 46 14 38 37 36 34 01 f0 } //1
		$a_01_3 = {0f 70 ca ff 0f 77 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}