
rule DDoS_Win32_Rovelobok_A{
	meta:
		description = "DDoS:Win32/Rovelobok.A,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 6f 62 6c 6f 78 20 48 61 63 6b 65 72 } //32 Roblox Hacker
		$a_01_1 = {76 00 65 00 72 00 74 00 69 00 63 00 6c 00 61 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 31 00 6e 00 74 00 65 00 72 00 78 00 5f 00 73 00 74 00 6f 00 6f 00 66 00 2f 00 6c 00 6f 00 67 00 5f 00 65 00 78 00 2e 00 70 00 68 00 70 00 } //8 verticlan.com/1nterx_stoof/log_ex.php
		$a_01_2 = {31 00 6e 00 74 00 65 00 72 00 78 00 5f 00 73 00 74 00 6f 00 6f 00 66 00 2f 00 6c 00 6f 00 67 00 5f 00 70 00 69 00 6e 00 67 00 2e 00 70 00 68 00 70 00 } //8 1nterx_stoof/log_ping.php
		$a_01_3 = {75 00 70 00 64 00 61 00 74 00 65 00 65 00 65 00 2e 00 65 00 78 00 65 00 } //4 updateee.exe
		$a_01_4 = {73 00 6c 00 6f 00 77 00 6c 00 6f 00 72 00 69 00 73 00 } //2 slowloris
		$a_01_5 = {4a 00 61 00 76 00 61 00 5f 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 } //2 Java_Updater
	condition:
		((#a_01_0  & 1)*32+(#a_01_1  & 1)*8+(#a_01_2  & 1)*8+(#a_01_3  & 1)*4+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=44
 
}