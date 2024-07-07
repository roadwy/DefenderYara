
rule VirTool_Win32_CeeInject_LN_bit{
	meta:
		description = "VirTool:Win32/CeeInject.LN!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b 15 90 01 04 88 84 15 90 09 24 00 be 90 01 04 8d bd 90 01 04 b9 06 00 00 00 f3 a5 a4 0f bf 05 90 01 04 0f be 15 90 01 04 8b ca 99 90 00 } //1
		$a_03_1 = {f7 f9 8b 15 90 01 04 88 84 15 90 09 11 00 0f bf 05 90 01 04 0f be 15 90 01 04 8b ca 99 90 00 } //1
		$a_01_2 = {53 6e 75 62 43 69 63 61 6c 61 2e 62 66 4a } //1 SnubCicala.bfJ
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}