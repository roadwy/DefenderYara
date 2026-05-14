
rule Trojan_Win32_LummaS_B{
	meta:
		description = "Trojan:Win32/LummaS.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 53 00 74 00 61 00 72 00 74 00 3d 00 22 00 70 00 79 00 74 00 68 00 6f 00 6e 00 77 00 2e 00 65 00 78 00 65 00 22 00 } //1 --processStart="pythonw.exe"
		$a_00_1 = {2d 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2d 00 73 00 74 00 61 00 72 00 74 00 2d 00 61 00 72 00 67 00 73 00 3d 00 } //1 --process-start-args=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}