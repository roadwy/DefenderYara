
rule TrojanProxy_Win32_Mitglieder_gen_A{
	meta:
		description = "TrojanProxy:Win32/Mitglieder.gen!A,SIGNATURE_TYPE_PEHSTR,09 00 08 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 73 3f 70 3d 25 6c 75 26 69 64 3d 25 73 26 65 3d 25 6c 75 } //02 00  %s?p=%lu&id=%s&e=%lu
		$a_01_1 = {4b 65 79 3d 31 2e 32 2e 33 2e 34 } //02 00  Key=1.2.3.4
		$a_01_2 = {62 61 6e 5f 6c 69 73 74 2e 74 78 74 } //02 00  ban_list.txt
		$a_01_3 = {69 66 20 65 78 69 73 74 20 25 31 20 67 6f 74 6f 20 6c } //02 00  if exist %1 goto l
		$a_01_4 = {75 69 64 00 70 6f 72 74 } //01 00  極d潰瑲
		$a_01_5 = {48 54 54 50 2f 31 2e 31 20 32 30 30 20 43 6f 6e 6e 65 63 74 69 6f 6e } //01 00  HTTP/1.1 200 Connection
		$a_01_6 = {4d 61 78 49 50 43 6f 6e 6e } //01 00  MaxIPConn
		$a_01_7 = {2d 75 70 64 00 } //01 00 
		$a_01_8 = {66 72 75 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}