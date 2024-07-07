
rule VirTool_Win32_Ninject_A{
	meta:
		description = "VirTool:Win32/Ninject.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 14 10 33 ca 8b 85 90 01 04 88 8c 05 90 01 04 8b 85 90 01 04 83 c0 01 90 00 } //1
		$a_03_1 = {0f be 14 10 33 ca 8b 45 90 01 01 03 85 90 01 04 88 08 8b 45 90 01 01 03 85 90 01 04 0f be 08 8b 85 90 01 04 99 f7 bd 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}