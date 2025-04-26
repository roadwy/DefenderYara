
rule Trojan_Win32_ThemFakSvc_SP_MSR{
	meta:
		description = "Trojan:Win32/ThemFakSvc.SP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 54 6c 73 48 65 6c 70 65 72 58 42 75 6e 64 6c 65 72 5c 52 65 6c 65 61 73 65 5c 58 42 75 6e 64 6c 65 72 54 6c 73 48 65 6c 70 65 72 2e 70 64 62 } //1 \TlsHelperXBundler\Release\XBundlerTlsHelper.pdb
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 41 00 73 00 73 00 69 00 73 00 74 00 61 00 6e 00 74 00 } //1 Windows Update Assistant
		$a_01_2 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 svchost.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}