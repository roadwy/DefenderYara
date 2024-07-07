
rule VirTool_Win32_Injector_IB{
	meta:
		description = "VirTool:Win32/Injector.IB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {c6 45 ce 00 6a 2e 68 90 01 04 6a 0b 8d 8d 38 ff ff ff 51 e8 90 01 04 83 c4 10 a1 90 01 04 0f af 05 90 01 04 99 b9 b9 41 c7 00 f7 f9 83 f8 01 90 00 } //1
		$a_03_1 = {eb 09 8b 45 e0 83 c0 01 89 45 e0 81 7d e0 e8 03 00 00 7f 90 01 01 c7 45 d8 00 00 00 00 8d 4d d8 51 8d 4d e4 e8 90 00 } //1
		$a_03_2 = {c6 45 fe 30 c6 45 fc 78 c6 45 fd 41 c6 45 ff 61 0f be 45 fe 8b 4d 08 0f b6 11 3b c2 0f 85 90 01 04 0f be 45 fc 8b 4d 08 0f b6 51 01 3b c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}