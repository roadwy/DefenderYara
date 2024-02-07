
rule Trojan_Win32_RundllLolBin_AH{
	meta:
		description = "Trojan:Win32/RundllLolBin.AH,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  schtasks.exe
		$a_00_1 = {63 00 72 00 65 00 61 00 74 00 65 00 } //01 00  create
		$a_00_2 = {2e 00 6a 00 73 00 } //01 00  .js
		$a_00_3 = {61 00 6e 00 79 00 64 00 65 00 73 00 6b 00 } //00 00  anydesk
	condition:
		any of ($a_*)
 
}