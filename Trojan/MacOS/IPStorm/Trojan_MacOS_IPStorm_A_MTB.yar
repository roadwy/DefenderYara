
rule Trojan_MacOS_IPStorm_A_MTB{
	meta:
		description = "Trojan:MacOS/IPStorm.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 6f 72 6d 2f 6d 61 6c 77 61 72 65 2d 67 75 61 72 64 } //01 00  storm/malware-guard
		$a_02_1 = {73 74 6f 72 6d 2f 70 6f 77 65 72 73 68 65 6c 6c 2e 90 02 10 2e 53 74 61 72 74 50 72 6f 63 65 73 73 90 00 } //01 00 
		$a_00_2 = {73 74 6f 72 6d 2f 62 61 63 6b 73 68 65 6c 6c 2e 53 74 61 72 74 53 65 72 76 65 72 } //01 00  storm/backshell.StartServer
		$a_02_3 = {66 69 6c 65 74 72 61 6e 73 66 65 72 2e 90 02 20 2e 45 6e 73 75 72 65 41 75 74 6f 53 74 61 72 74 90 00 } //01 00 
		$a_00_4 = {73 74 6f 72 6d 2f 63 6f 6d 6d 61 6e 64 65 72 2f 77 65 62 5f 61 70 70 2f 72 6f 75 74 65 72 } //01 00  storm/commander/web_app/router
		$a_00_5 = {61 76 62 79 70 61 73 73 } //00 00  avbypass
		$a_00_6 = {5d 04 00 00 } //7c 4b 
	condition:
		any of ($a_*)
 
}