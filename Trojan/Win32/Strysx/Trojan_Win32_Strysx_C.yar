
rule Trojan_Win32_Strysx_C{
	meta:
		description = "Trojan:Win32/Strysx.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 03 00 "
		
	strings :
		$a_02_0 = {eb ca 8d 75 e4 e8 90 01 02 00 00 8d 4d b8 51 e8 90 01 02 00 00 89 7d c8 ff 55 ec 8b 7d 08 89 45 b4 8b 10 57 8b c8 ff 52 90 01 01 ff d3 90 00 } //01 00 
		$a_01_1 = {62 6f 74 2e 64 6c 6c 00 5f 57 4c 45 76 65 6e 74 53 74 61 72 74 53 68 65 6c 6c 40 34 00 } //01 00 
		$a_01_2 = {69 64 00 00 5f 43 72 65 61 74 65 4d 6f 64 75 6c 65 40 30 00 } //01 00 
		$a_01_3 = {74 6f 63 6f 6c 2e 63 70 70 00 00 00 2e 6c 6f 67 } //00 00 
	condition:
		any of ($a_*)
 
}