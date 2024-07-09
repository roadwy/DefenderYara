
rule DDoS_Linux_Flooder_H_xp{
	meta:
		description = "DDoS:Linux/Flooder.H!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 6c 6f 6f 64 69 6e 67 20 49 50 3a 20 25 73 20 7c 20 50 4f 52 54 3a 20 25 64 20 20 7c 20 42 59 20 4d 4f 52 47 41 4e } //1 Flooding IP: %s | PORT: %d  | BY MORGAN
		$a_03_1 = {55 73 61 67 65 3a 20 25 73 [0-15] 5b 4c 49 53 54 2e 54 58 54 5d [0-15] 5b 54 49 4d 45 5d } //1
		$a_01_2 = {4d 53 53 51 4c 20 42 79 20 4d 4f 52 47 41 4e } //1 MSSQL By MORGAN
		$a_01_3 = {6d 73 73 71 6c 2e 63 } //1 mssql.c
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}