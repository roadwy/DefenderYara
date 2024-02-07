
rule Trojan_Win32_VB_PQ{
	meta:
		description = "Trojan:Win32/VB.PQ,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {5c 00 28 67 6c 9a 9f 53 0b 7a 8f 5e 90 02 04 5c 00 45 00 6d 00 61 00 69 00 6c 00 2e 00 76 00 62 00 70 00 90 00 } //0a 00 
		$a_02_1 = {48 00 45 00 4c 00 4f 00 90 02 20 41 00 55 00 54 00 48 00 20 00 4c 00 4f 00 47 00 49 00 4e 00 90 00 } //05 00 
		$a_00_2 = {64 00 61 00 70 00 68 00 61 00 2e 00 6e 00 65 00 74 00 } //01 00  dapha.net
		$a_00_3 = {4d 61 6b 65 6d 61 69 6c } //01 00  Makemail
		$a_00_4 = {74 78 74 73 65 72 76 65 72 } //01 00  txtserver
		$a_00_5 = {74 78 74 6b 65 79 6c 6f 67 } //00 00  txtkeylog
	condition:
		any of ($a_*)
 
}