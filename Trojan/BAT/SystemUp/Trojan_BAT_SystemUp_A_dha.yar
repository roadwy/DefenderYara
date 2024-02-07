
rule Trojan_BAT_SystemUp_A_dha{
	meta:
		description = "Trojan:BAT/SystemUp.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 4c 52 64 6c 6c 2e 64 6c 6c 00 47 65 74 43 75 72 72 65 6e 74 49 6e 74 65 72 6e 61 6c 5f 52 65 70 6f 72 74 52 6f 6c 6c 62 61 63 6b 45 76 65 6e 74 } //01 00 
		$a_00_1 = {48 61 6e 64 6c 65 53 68 65 6c 6c 00 50 72 6f 67 72 61 6d } //01 00 
		$a_80_2 = {53 79 73 74 65 6d 55 70 2e 50 72 6f 70 65 72 74 69 65 73 } //SystemUp.Properties  01 00 
		$a_00_3 = {42 45 41 53 44 5a 58 58 58 4d 45 4c } //01 00  BEASDZXXXMEL
		$a_00_4 = {59 45 50 54 52 55 50 54 41 53 4b 41 4d 45 4c 41 4e 41 5a } //01 00  YEPTRUPTASKAMELANAZ
		$a_00_5 = {53 74 61 72 53 68 65 6c 6c } //01 00  StarShell
		$a_00_6 = {53 68 65 6c 6c 57 72 69 74 65 4c 69 6e 65 } //01 00  ShellWriteLine
		$a_00_7 = {50 72 6f 63 65 73 73 53 68 65 6c 6c } //01 00  ProcessShell
		$a_80_8 = {53 79 73 74 65 6d 55 70 2e 65 78 65 } //SystemUp.exe  00 00 
	condition:
		any of ($a_*)
 
}