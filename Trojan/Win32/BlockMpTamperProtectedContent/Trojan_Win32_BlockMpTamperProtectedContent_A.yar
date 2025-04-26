
rule Trojan_Win32_BlockMpTamperProtectedContent_A{
	meta:
		description = "Trojan:Win32/BlockMpTamperProtectedContent.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {77 00 73 00 72 00 65 00 73 00 65 00 74 00 2e 00 65 00 78 00 65 00 } //1 wsreset.exe
	condition:
		((#a_00_0  & 1)*1) >=1
 
}