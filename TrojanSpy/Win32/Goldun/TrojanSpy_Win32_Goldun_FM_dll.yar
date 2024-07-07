
rule TrojanSpy_Win32_Goldun_FM_dll{
	meta:
		description = "TrojanSpy:Win32/Goldun.FM!dll,SIGNATURE_TYPE_PEHSTR,57 00 54 00 08 00 00 "
		
	strings :
		$a_01_0 = {2f 25 73 2f 6d 73 67 2e 70 68 70 3f 76 65 72 3d 25 73 26 65 78 74 76 65 72 3d 25 73 26 75 73 65 72 3d 25 73 26 6c 61 6e 67 3d } //1 /%s/msg.php?ver=%s&extver=%s&user=%s&lang=
		$a_01_1 = {2f 25 73 2f 6c 6f 67 69 6e 2e 70 68 70 3f 75 73 65 72 3d 25 73 26 6c 61 6e 67 3d 25 73 26 75 70 74 69 6d 65 3d 25 64 5f 64 5f 25 64 68 5f 25 64 6d 26 73 6f 63 6b 73 3d 30 26 76 65 72 3d 25 73 26 65 78 74 76 65 72 3d 25 73 26 77 69 6e 3d } //1 /%s/login.php?user=%s&lang=%s&uptime=%d_d_%dh_%dm&socks=0&ver=%s&extver=%s&win=
		$a_01_2 = {5c 73 70 6f 6f 6c 5c 64 65 73 6b 74 6f 70 73 2e 69 6e 69 } //3 \spool\desktops.ini
		$a_01_3 = {5c 73 70 6f 6f 6c 5c 63 2e 69 6e 69 } //3 \spool\c.ini
		$a_01_4 = {5c 73 70 6f 6f 6c 5c 65 67 2e 69 6e 69 } //3 \spool\eg.ini
		$a_01_5 = {65 2d 67 6f 6c 64 2e 63 6f 6d 2f 61 63 63 74 2f 6c 69 2e 61 73 70 } //20 e-gold.com/acct/li.asp
		$a_01_6 = {48 54 54 50 4d 61 69 6c 20 50 61 73 73 77 6f 72 64 } //30 HTTPMail Password
		$a_01_7 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 } //30 POP3 Password
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*20+(#a_01_6  & 1)*30+(#a_01_7  & 1)*30) >=84
 
}
rule TrojanSpy_Win32_Goldun_FM_dll_2{
	meta:
		description = "TrojanSpy:Win32/Goldun.FM!dll,SIGNATURE_TYPE_PEHSTR,33 00 2e 00 08 00 00 "
		
	strings :
		$a_01_0 = {2f 25 73 2f 66 69 6e 61 6c 2e 70 68 70 3f 76 65 72 3d 25 73 26 75 73 65 72 3d 25 73 26 73 69 74 65 3d 70 6f 73 74 } //1 /%s/final.php?ver=%s&user=%s&site=post
		$a_01_1 = {2f 25 73 2f 64 72 6f 70 2e 70 68 70 3f 76 65 72 3d 25 73 26 73 69 74 65 3d 70 6f 73 74 26 75 73 65 72 3d 25 73 25 73 } //1 /%s/drop.php?ver=%s&site=post&user=%s%s
		$a_01_2 = {2f 25 73 2f 6d 61 69 6c 2e 70 68 70 3f 76 65 72 3d 25 73 26 65 78 74 76 65 72 3d 25 73 26 75 73 65 72 3d 25 73 26 6c 61 6e 67 3d 25 73 26 77 69 6e } //1 /%s/mail.php?ver=%s&extver=%s&user=%s&lang=%s&win
		$a_01_3 = {62 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 2e 00 70 00 6f 00 73 00 74 00 62 00 61 00 6e 00 6b 00 2e 00 64 00 65 00 2f 00 61 00 70 00 70 00 2f 00 75 00 65 00 62 00 65 00 72 00 77 00 65 00 69 00 73 00 75 00 6e 00 67 00 } //5 banking.postbank.de/app/ueberweisung
		$a_01_4 = {62 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 2e 00 70 00 6f 00 73 00 74 00 62 00 61 00 6e 00 6b 00 2e 00 64 00 65 00 2f 00 61 00 70 00 70 00 2f 00 6c 00 65 00 67 00 69 00 74 00 69 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 } //5 banking.postbank.de/app/legitimation.
		$a_01_5 = {70 00 6f 00 73 00 74 00 62 00 61 00 6e 00 6b 00 2e 00 64 00 65 00 2f 00 61 00 70 00 70 00 2f 00 66 00 69 00 6e 00 61 00 6e 00 7a 00 73 00 74 00 61 00 74 00 75 00 73 00 2e 00 69 00 6e 00 69 00 74 00 2e 00 64 00 6f 00 } //5 postbank.de/app/finanzstatus.init.do
		$a_01_6 = {5c 73 70 6f 6f 6c 5c 64 65 73 6b 74 6f 70 73 2e 69 6e 69 } //20 \spool\desktops.ini
		$a_01_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //20 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*20+(#a_01_7  & 1)*20) >=46
 
}