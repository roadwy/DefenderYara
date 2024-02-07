
rule Trojan_AndroidOS_Tangbot_A{
	meta:
		description = "Trojan:AndroidOS/Tangbot.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 65 6e 64 5f 6c 6f 67 5f 69 6e 6a 65 63 74 73 } //02 00  send_log_injects
		$a_01_1 = {4c 73 74 61 74 69 6f 6e 2f 66 61 69 72 6c 79 2f 62 65 63 61 75 73 65 } //02 00  Lstation/fairly/because
		$a_01_2 = {72 65 73 65 74 4c 6f 61 64 41 70 70 } //00 00  resetLoadApp
	condition:
		any of ($a_*)
 
}