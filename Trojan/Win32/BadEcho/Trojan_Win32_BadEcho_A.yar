
rule Trojan_Win32_BadEcho_A{
	meta:
		description = "Trojan:Win32/BadEcho.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //5 cmd.exe
		$a_02_1 = {2f 00 73 00 20 00 2f 00 64 00 20 00 2f 00 63 00 [0-08] 65 00 63 00 68 00 6f 00 20 00 25 00 [0-04] 3a 00 [0-10] 3d 00 25 00 } //5
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*5) >=10
 
}