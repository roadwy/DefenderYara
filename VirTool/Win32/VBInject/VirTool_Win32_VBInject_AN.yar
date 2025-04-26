
rule VirTool_Win32_VBInject_AN{
	meta:
		description = "VirTool:Win32/VBInject.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 50 00 42 00 5f 00 53 00 74 00 75 00 62 00 20 00 7b 00 53 00 63 00 72 00 61 00 6d 00 62 00 6c 00 65 00 64 00 7d 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 \PB_Stub {Scrambled}\Project1.vbp
		$a_01_1 = {50 50 56 44 50 45 58 51 00 00 00 00 6d 64 6c 45 6e 6a 65 6b 74 6f 72 00 4d 6f 64 75 6c 65 31 00 4d 6f 64 75 6c 65 35 00 6d 64 6c 4d 61 69 6e 00 50 72 6f 6a 65 63 74 31 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}