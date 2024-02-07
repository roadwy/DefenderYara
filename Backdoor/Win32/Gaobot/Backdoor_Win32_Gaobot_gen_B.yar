
rule Backdoor_Win32_Gaobot_gen_B{
	meta:
		description = "Backdoor:Win32/Gaobot.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0c 00 11 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 63 2e 70 68 70 3f 26 70 3d 25 69 26 76 3d 25 69 } //01 00  rec.php?&p=%i&v=%i
		$a_00_1 = {72 65 64 69 72 65 63 74 2e 68 74 74 70 } //01 00  redirect.http
		$a_00_2 = {72 65 64 69 72 65 63 74 2e 73 6f 63 6b 73 } //01 00  redirect.socks
		$a_00_3 = {72 65 64 69 72 65 63 74 2e 73 74 6f 70 } //01 00  redirect.stop
		$a_01_4 = {41 75 74 6f 73 74 61 72 74 2e 6e 65 74 } //01 00  Autostart.net
		$a_01_5 = {48 6f 73 74 3a 20 25 73 3a 25 64 } //01 00  Host: %s:%d
		$a_01_6 = {43 52 65 64 69 72 65 63 74 42 61 73 65 } //01 00  CRedirectBase
		$a_01_7 = {43 52 65 64 69 72 65 63 74 48 54 54 50 5f 54 68 72 65 61 64 } //01 00  CRedirectHTTP_Thread
		$a_01_8 = {43 52 65 64 69 72 65 63 74 53 4f 43 4b 53 5f 54 68 72 65 61 64 } //01 00  CRedirectSOCKS_Thread
		$a_01_9 = {53 65 72 76 65 72 3a 20 68 74 74 70 70 72 6f 78 79 } //01 00  Server: httpproxy
		$a_00_10 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 63 6c 6f 73 65 } //01 00  Proxy-Connection: close
		$a_01_11 = {43 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 25 73 3a 25 64 20 66 61 69 6c 65 64 21 } //01 00  Connection to %s:%d failed!
		$a_00_12 = {48 54 54 50 2f 31 2e 30 20 32 30 30 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 65 73 74 61 62 6c 69 73 68 65 64 } //01 00  HTTP/1.0 200 Connection established
		$a_01_13 = {70 78 62 67 31 } //01 00  pxbg1
		$a_01_14 = {62 6c 61 20 62 6c 61 20 62 6c 61 } //01 00  bla bla bla
		$a_01_15 = {67 5f 70 43 6f 6d 6d 61 6e 64 73 } //01 00  g_pCommands
		$a_01_16 = {67 5f 70 49 6e 73 74 61 6c 6c 65 72 } //00 00  g_pInstaller
	condition:
		any of ($a_*)
 
}