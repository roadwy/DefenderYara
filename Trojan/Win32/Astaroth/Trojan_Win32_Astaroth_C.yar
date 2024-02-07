
rule Trojan_Win32_Astaroth_C{
	meta:
		description = "Trojan:Win32/Astaroth.C,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //05 00  cmd
		$a_00_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 } //05 00  Internet Explorer
		$a_00_2 = {45 00 78 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 2e 00 65 00 78 00 65 00 } //05 00  ExtExport.exe
		$a_00_3 = {5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 4c 00 69 00 62 00 72 00 61 00 72 00 69 00 65 00 73 00 5c 00 } //00 00  \Users\Public\Libraries\
	condition:
		any of ($a_*)
 
}