
rule Trojan_Win32_SuspSqlpsExec_A{
	meta:
		description = "Trojan:Win32/SuspSqlpsExec.A,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 00 71 00 6c 00 70 00 73 00 2e 00 65 00 78 00 65 00 } //10 sqlps.exe
		$a_00_1 = {6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //1 net.webclient
		$a_00_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //1 invoke-expression
		$a_00_3 = {69 00 65 00 78 00 28 00 } //1 iex(
		$a_00_4 = {24 00 65 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 63 00 6d 00 64 00 } //-20 $env:tempcmd
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*-20) >=11
 
}