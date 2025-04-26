
rule Trojan_Win32_RemoteSysDisc_A{
	meta:
		description = "Trojan:Win32/RemoteSysDisc.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {67 00 65 00 74 00 2d 00 61 00 64 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 } //2 get-adcomputer
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2) >=3
 
}