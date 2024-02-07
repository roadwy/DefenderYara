
rule DDoS_BAT_Ormerga_A_bit{
	meta:
		description = "DDoS:BAT/Ormerga.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {49 6d 48 65 72 65 } //02 00  ImHere
		$a_01_1 = {47 65 74 41 74 74 61 63 6b } //02 00  GetAttack
		$a_01_2 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 64 00 49 00 49 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  \temp\dIIhost.exe
		$a_01_3 = {2f 00 62 00 6f 00 74 00 5f 00 64 00 61 00 74 00 61 00 2f 00 73 00 65 00 72 00 76 00 65 00 72 00 5f 00 6c 00 69 00 73 00 74 00 2f 00 73 00 65 00 72 00 76 00 65 00 72 00 } //01 00  /bot_data/server_list/server
		$a_01_4 = {62 00 6f 00 74 00 2f 00 6f 00 75 00 74 00 70 00 75 00 74 00 } //01 00  bot/output
		$a_01_5 = {2f 00 62 00 6f 00 74 00 5f 00 64 00 61 00 74 00 61 00 2f 00 64 00 64 00 6f 00 73 00 5f 00 6c 00 69 00 73 00 74 00 2f 00 64 00 64 00 6f 00 73 00 } //00 00  /bot_data/ddos_list/ddos
	condition:
		any of ($a_*)
 
}