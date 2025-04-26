
rule VirTool_Win32_Vbcrypt_P{
	meta:
		description = "VirTool:Win32/Vbcrypt.P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 2e 64 6c 6c [0-08] 53 68 65 6c 6c 45 78 65 63 75 74 65 [0-60] 2e 00 65 00 78 00 65 00 00 00 [0-08] 64 00 66 00 64 00 } //1
		$a_00_1 = {5c 00 41 00 59 00 3a 00 5c 00 63 00 6f 00 64 00 65 00 5c 00 70 00 72 00 6f 00 67 00 5c 00 6d 00 79 00 5c 00 6d 00 79 00 70 00 72 00 6f 00 67 00 2e 00 76 00 62 00 70 00 } //1 \AY:\code\prog\my\myprog.vbp
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}