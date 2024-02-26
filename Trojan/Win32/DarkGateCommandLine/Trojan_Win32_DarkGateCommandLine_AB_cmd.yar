
rule Trojan_Win32_DarkGateCommandLine_AB_cmd{
	meta:
		description = "Trojan:Win32/DarkGateCommandLine.AB!cmd,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  cmd.exe
		$a_00_1 = {63 00 75 00 72 00 6c 00 } //01 00  curl
		$a_00_2 = {41 00 75 00 74 00 6f 00 69 00 74 00 33 00 2e 00 65 00 78 00 65 00 } //01 00  Autoit3.exe
		$a_00_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //01 00  http://
		$a_00_4 = {2e 00 61 00 75 00 33 00 } //00 00  .au3
	condition:
		any of ($a_*)
 
}