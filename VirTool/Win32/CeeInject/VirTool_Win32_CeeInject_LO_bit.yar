
rule VirTool_Win32_CeeInject_LO_bit{
	meta:
		description = "VirTool:Win32/CeeInject.LO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f3 a5 66 a5 a4 5e a0 90 01 04 02 05 90 01 04 0f bf 15 90 01 04 88 84 15 90 01 04 8a 0d 90 01 04 2a 0d 90 01 04 0f bf 05 90 01 04 88 8c 05 90 00 } //1
		$a_03_1 = {f7 f9 0f bf 15 90 01 04 88 84 15 90 09 11 00 0f bf 05 90 01 04 0f bf 15 90 01 04 8b ca 99 90 00 } //1
		$a_01_2 = {54 68 6f 6e 67 2e 6a } //1 Thong.j
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}