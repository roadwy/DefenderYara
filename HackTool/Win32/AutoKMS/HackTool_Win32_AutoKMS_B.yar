
rule HackTool_Win32_AutoKMS_B{
	meta:
		description = "HackTool:Win32/AutoKMS.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 00 4d 00 53 00 49 00 6e 00 6a 00 65 00 63 00 74 00 2e 00 64 00 6c 00 6c 00 } //1 KMSInject.dll
		$a_01_1 = {6d 00 65 00 70 00 68 00 69 00 73 00 74 00 6f 00 6f 00 6f 00 32 00 20 00 2d 00 20 00 54 00 4e 00 43 00 54 00 52 00 2e 00 63 00 6f 00 6d 00 } //1 mephistooo2 - TNCTR.com
		$a_01_2 = {53 00 61 00 6e 00 61 00 6c 00 20 00 4b 00 4d 00 53 00 20 00 53 00 75 00 6e 00 75 00 63 00 75 00 } //1 Sanal KMS Sunucu
		$a_01_3 = {53 70 70 45 78 74 43 6f 6d 4f 62 6a 50 61 74 63 68 65 72 2d 6b 6d 73 5c 44 65 62 75 67 5c 78 36 34 5c 4b 4d 53 2e 70 64 62 } //1 SppExtComObjPatcher-kms\Debug\x64\KMS.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}