
rule Trojan_Win32_WebToos_A{
	meta:
		description = "Trojan:Win32/WebToos.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 7c 25 73 7c 31 7c 25 73 7c 25 64 7c 31 7c 31 35 7c 35 7c 25 64 7c } //01 00  2|%s|1|%s|%d|1|15|5|%d|
		$a_01_1 = {00 73 76 63 68 30 73 74 2e 65 78 65 00 } //01 00 
		$a_01_2 = {25 73 20 64 39 3a 6c 69 6e 6b 5f 6c 69 73 74 35 31 3a 63 6f 6e 74 69 6e 75 65 7c } //01 00  %s d9:link_list51:continue|
		$a_01_3 = {7c 39 3a 74 61 73 6b 5f 6c 69 73 74 6c 25 73 65 65 } //01 00  |9:task_listl%see
		$a_00_4 = {50 72 65 73 74 6f 2f 32 2e 7c 44 26 38 26 31 38 7c 2e 7c 44 26 39 30 26 38 39 30 7c 20 56 65 72 73 69 6f 6e 2f 7c 44 26 7c } //00 00  Presto/2.|D&8&18|.|D&90&890| Version/|D&|
	condition:
		any of ($a_*)
 
}