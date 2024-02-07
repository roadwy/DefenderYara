
rule Backdoor_Win32_Turla_A_dha{
	meta:
		description = "Backdoor:Win32/Turla.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 54 4f 50 7c 4b 49 4c 4c 7c } //01 00  STOP|KILL|
		$a_01_1 = {4f 50 45 52 7c 53 6e 69 66 66 65 72 } //01 00  OPER|Sniffer
		$a_01_2 = {25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 7c 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 7c 25 73 7c 73 7c } //01 00  %02d/%02d/%02d|%02d:%02d:%02d|%s|s|
		$a_01_3 = {6e 6f 5f 73 65 72 76 65 72 5f 68 69 6a 61 63 6b } //00 00  no_server_hijack
		$a_00_4 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}