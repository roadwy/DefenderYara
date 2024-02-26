
rule Trojan_Win32_DarkGate_AC_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.AC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  powershell.exe
		$a_00_1 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 57 00 65 00 62 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 } //01 00  Invoke-WebRequest
		$a_00_2 = {63 00 75 00 72 00 6c 00 } //01 00  curl
		$a_00_3 = {41 00 75 00 74 00 6f 00 69 00 74 00 33 00 2e 00 65 00 78 00 65 00 } //01 00  Autoit3.exe
		$a_00_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //01 00  http://
		$a_00_5 = {2e 00 61 00 75 00 33 00 } //00 00  .au3
	condition:
		any of ($a_*)
 
}