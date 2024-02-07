
rule Backdoor_Linux_Tusnami_E_xp{
	meta:
		description = "Backdoor:Linux/Tusnami.E!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {7c 7c 20 63 64 20 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 2f 43 68 65 61 74 73 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 90 02 10 2e 73 68 3b 20 73 68 20 90 02 10 2e 73 68 3b 20 74 66 74 70 90 00 } //01 00 
		$a_00_1 = {48 61 63 6b 65 72 53 63 61 6e } //01 00  HackerScan
		$a_00_2 = {53 74 61 72 74 54 68 65 4c 65 6c 7a } //01 00  StartTheLelz
		$a_00_3 = {73 65 6e 64 48 54 54 50 } //00 00  sendHTTP
	condition:
		any of ($a_*)
 
}