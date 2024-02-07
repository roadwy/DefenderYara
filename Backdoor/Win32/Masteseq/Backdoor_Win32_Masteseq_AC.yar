
rule Backdoor_Win32_Masteseq_AC{
	meta:
		description = "Backdoor:Win32/Masteseq.AC,SIGNATURE_TYPE_PEHSTR,09 00 09 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {25 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  %s\Internet Explorer\iexplorer.exe
		$a_01_2 = {25 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00  %s\Internet Explorer\iexplore.exe
		$a_01_3 = {50 4f 53 54 20 2f 63 67 69 2d 62 69 6e 2f 63 67 69 5f 70 72 6f 78 79 3f 63 6c 3d 31 20 48 54 54 50 2f 31 2e 31 } //01 00  POST /cgi-bin/cgi_proxy?cl=1 HTTP/1.1
		$a_01_4 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 35 2e 30 3b 20 57 69 6e 64 6f 77 73 20 39 35 29 } //01 00  User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows 95)
		$a_01_5 = {48 6f 73 74 3a 20 25 73 } //01 00  Host: %s
		$a_01_6 = {6d 73 67 71 75 65 75 65 5f 6d 73 67 31 5f 64 61 74 61 5f 25 30 38 58 } //01 00  msgqueue_msg1_data_%08X
		$a_01_7 = {6d 5f 73 65 72 76 65 72 5f 77 6f 72 6b 5f 74 69 6d 65 } //01 00  m_server_work_time
		$a_01_8 = {5c 74 65 6d 70 5f 25 64 2e 62 61 74 } //01 00  \temp_%d.bat
		$a_01_9 = {53 4f 46 54 57 41 52 45 5c 4e 75 6d 65 67 61 } //00 00  SOFTWARE\Numega
	condition:
		any of ($a_*)
 
}