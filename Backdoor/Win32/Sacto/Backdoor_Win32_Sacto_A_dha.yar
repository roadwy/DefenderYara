
rule Backdoor_Win32_Sacto_A_dha{
	meta:
		description = "Backdoor:Win32/Sacto.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 53 73 6c 4d 4d } //02 00  \SslMM
		$a_01_1 = {00 53 53 4c 4d 4d 00 } //02 00 
		$a_01_2 = {63 6f 6e 6e 65 63 74 20 73 75 63 20 62 65 67 69 6e 20 72 65 63 76 } //05 00  connect suc begin recv
		$a_01_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b 20 55 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 7a 68 2d 45 4e 3b 20 72 76 3a 31 2e 37 2e 31 32 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 37 31 39 20 46 69 72 65 66 6f 78 2f 31 2e 30 2e 37 } //05 00  User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/20100719 Firefox/1.0.7
		$a_01_4 = {5c 00 4f 00 66 00 66 00 69 00 63 00 65 00 20 00 53 00 74 00 61 00 72 00 74 00 2e 00 6c 00 6e 00 6b 00 } //05 00  \Office Start.lnk
		$a_01_5 = {50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 77 73 3a 25 64 2f 25 64 25 73 25 64 48 54 54 50 2f 31 2e 31 } //00 00  POST http://%ws:%d/%d%s%dHTTP/1.1
		$a_00_6 = {80 10 00 00 01 51 a0 17 ab 61 } //7c 3c 
	condition:
		any of ($a_*)
 
}