
rule Trojan_Win32_ClickFix_SKDA{
	meta:
		description = "Trojan:Win32/ClickFix.SKDA,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 } //10
		$a_00_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
		$a_02_2 = {2e 00 70 00 68 00 70 00 [0-30] 2d 00 6f 00 [0-ff] 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=12
 
}