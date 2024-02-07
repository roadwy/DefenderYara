
rule Trojan_Win32_FoxBlade_C_dha{
	meta:
		description = "Trojan:Win32/FoxBlade.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {20 00 2d 00 61 00 20 00 22 00 90 01 02 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_00_1 = {57 69 7a 61 72 64 2e 64 6c 6c } //01 00  Wizard.dll
		$a_01_2 = {8d 4e fc 8b 01 33 c2 8b 11 4f 89 06 8d 31 85 ff 7f ee 8b 13 81 32 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}