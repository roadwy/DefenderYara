
rule Trojan_Win32_ShortPipe_A_dha{
	meta:
		description = "Trojan:Win32/ShortPipe.A!dha,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  wscript.exe
		$a_01_1 = {74 00 72 00 61 00 73 00 68 00 2e 00 64 00 61 00 74 00 } //01 00  trash.dat
		$a_01_2 = {74 00 72 00 61 00 73 00 68 00 2e 00 64 00 6c 00 6c 00 } //01 00  trash.dll
		$a_01_3 = {2f 00 2f 00 65 00 3a 00 76 00 62 00 53 00 63 00 72 00 69 00 70 00 74 00 } //01 00  //e:vbScript
		$a_01_4 = {2f 00 2f 00 62 00 } //00 00  //b
	condition:
		any of ($a_*)
 
}