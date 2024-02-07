
rule DDoS_Win32_Nitol_Q_bit{
	meta:
		description = "DDoS:Win32/Nitol.Q!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c0 03 33 d2 0f af c6 f7 74 24 } //01 00 
		$a_01_1 = {25 63 25 63 25 63 25 63 25 63 2e 65 78 65 00 } //01 00 
		$a_01_2 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //01 00  HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_01_3 = {64 64 6f 73 2e 74 66 } //01 00  ddos.tf
		$a_01_4 = {31 39 32 2e 31 36 38 2e 31 2e 32 34 34 } //01 00  192.168.1.244
		$a_01_5 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 25 73 25 73 } //00 00  Referer: http://%s%s
	condition:
		any of ($a_*)
 
}