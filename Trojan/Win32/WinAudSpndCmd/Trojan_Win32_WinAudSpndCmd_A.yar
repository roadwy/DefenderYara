
rule Trojan_Win32_WinAudSpndCmd_A{
	meta:
		description = "Trojan:Win32/WinAudSpndCmd.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {70 00 73 00 73 00 75 00 73 00 70 00 65 00 6e 00 64 00 [0-0f] 77 00 69 00 6e 00 61 00 75 00 64 00 69 00 74 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}