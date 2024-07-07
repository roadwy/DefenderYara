
rule VirTool_Win32_Injector_CI{
	meta:
		description = "VirTool:Win32/Injector.CI,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {bb 85 3b ae db 8b 95 cc fd ff ff e8 90 01 02 00 00 89 45 f0 90 00 } //5
		$a_03_1 = {bb 93 35 df 85 8b 95 cc fd ff ff e8 90 01 02 00 00 89 45 ec 90 00 } //5
		$a_03_2 = {bb 53 13 c1 78 8b 95 cc fd ff ff e8 90 01 02 00 00 89 45 e4 90 00 } //5
		$a_03_3 = {02 00 01 00 8d 85 90 01 02 ff ff 50 ff b5 90 01 02 ff ff ff 55 ec 64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 40 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*1) >=16
 
}