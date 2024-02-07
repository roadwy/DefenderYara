
rule Trojan_Win32_Powessere_M{
	meta:
		description = "Trojan:Win32/Powessere.M,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //01 00  powershell.exe
		$a_00_1 = {28 00 47 00 65 00 74 00 2d 00 49 00 74 00 65 00 6d 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 } //01 00  (Get-ItemProperty
		$a_02_2 = {72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 3a 00 3a 00 48 00 4b 00 90 01 04 5c 00 5c 00 53 00 3f 00 3f 00 3f 00 77 00 61 00 72 00 65 00 5c 00 5c 00 90 00 } //01 00 
		$a_00_3 = {69 00 65 00 78 00 } //00 00  iex
	condition:
		any of ($a_*)
 
}