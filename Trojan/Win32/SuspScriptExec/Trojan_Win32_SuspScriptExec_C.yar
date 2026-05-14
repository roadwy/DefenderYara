
rule Trojan_Win32_SuspScriptExec_C{
	meta:
		description = "Trojan:Win32/SuspScriptExec.C,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {29 00 2e 00 62 00 36 00 34 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00 } //1 ).b64decode(
		$a_00_1 = {29 00 2e 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00 } //1 ).decode(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}