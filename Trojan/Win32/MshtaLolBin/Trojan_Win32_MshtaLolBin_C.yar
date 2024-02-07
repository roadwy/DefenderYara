
rule Trojan_Win32_MshtaLolBin_C{
	meta:
		description = "Trojan:Win32/MshtaLolBin.C,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 } //01 00  schtasks
		$a_00_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //01 00  /create
		$a_00_2 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 } //01 00  mshta.exe
		$a_00_3 = {2e 00 68 00 74 00 61 00 } //01 00  .hta
		$a_00_4 = {6f 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 } //00 00  onlogon
	condition:
		any of ($a_*)
 
}