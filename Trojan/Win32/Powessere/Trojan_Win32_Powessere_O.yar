
rule Trojan_Win32_Powessere_O{
	meta:
		description = "Trojan:Win32/Powessere.O,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_00_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 } //01 00  javascript:
		$a_00_2 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 } //01 00  ActiveXObject(
		$a_00_3 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  wscript.shell
		$a_02_4 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 43 00 55 00 5c 00 90 02 04 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 90 00 } //01 00 
		$a_00_5 = {3b 00 65 00 76 00 61 00 6c 00 28 00 } //00 00  ;eval(
	condition:
		any of ($a_*)
 
}