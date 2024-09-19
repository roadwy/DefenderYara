
rule Trojan_Win32_SuspExec_YY{
	meta:
		description = "Trojan:Win32/SuspExec.YY,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //10 cmd.exe
		$a_02_1 = {61 00 75 00 74 00 6f 00 69 00 74 00 33 00 2e 00 65 00 78 00 65 00 20 00 [0-ff] 2e 00 61 00 33 00 78 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}