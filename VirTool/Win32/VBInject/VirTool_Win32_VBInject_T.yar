
rule VirTool_Win32_VBInject_T{
	meta:
		description = "VirTool:Win32/VBInject.T,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 56 00 69 00 64 00 65 00 6f 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 } //01 00  from Win32_VideoController
		$a_01_1 = {56 00 4d 00 77 00 61 00 72 00 65 00 20 00 53 00 56 00 47 00 41 00 } //01 00  VMware SVGA
		$a_01_2 = {53 00 33 00 20 00 54 00 72 00 69 00 6f 00 33 00 32 00 2f 00 36 00 34 00 } //01 00  S3 Trio32/64
		$a_01_3 = {53 00 61 00 6e 00 64 00 62 00 6f 00 78 00 69 00 65 00 20 00 } //01 00  Sandboxie 
		$a_01_4 = {44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 21 00 } //01 00  Detected!
		$a_01_5 = {5b 00 43 00 57 00 53 00 61 00 6e 00 64 00 62 00 6f 00 78 00 } //01 00  [CWSandbox
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}