
rule DDoS_Linux_Flooder_H_xp{
	meta:
		description = "DDoS:Linux/Flooder.H!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 6c 6f 6f 64 69 6e 67 20 49 50 3a 20 25 73 20 7c 20 50 4f 52 54 3a 20 25 64 20 20 7c 20 42 59 20 4d 4f 52 47 41 4e } //01 00  Flooding IP: %s | PORT: %d  | BY MORGAN
		$a_03_1 = {55 73 61 67 65 3a 20 25 73 90 02 15 5b 4c 49 53 54 2e 54 58 54 5d 90 02 15 5b 54 49 4d 45 5d 90 00 } //01 00 
		$a_01_2 = {4d 53 53 51 4c 20 42 79 20 4d 4f 52 47 41 4e } //01 00  MSSQL By MORGAN
		$a_01_3 = {6d 73 73 71 6c 2e 63 } //00 00  mssql.c
		$a_00_4 = {5d 04 00 } //00 d3 
	condition:
		any of ($a_*)
 
}