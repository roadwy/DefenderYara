
rule VirTool_Win32_Injector_FP{
	meta:
		description = "VirTool:Win32/Injector.FP,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 85 ad fb ff ff e8 c6 85 ae fb ff ff f1 c6 85 af fb ff ff b9 } //1
		$a_01_1 = {83 f0 8b 8d 8d ad fb ff ff 8b 55 bc 01 ca 88 02 ff 45 bc 83 7d bc 1d } //1
		$a_01_2 = {c7 00 07 00 01 00 8d 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}