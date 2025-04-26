
rule Trojan_Win32_Vidar_PD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PD!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {55 30 56 4d 52 55 4e 55 49 47 35 68 62 57 56 66 62 32 35 66 59 32 46 79 5a 43 77 67 5a 58 68 77 61 58 4a 68 64 47 6c 76 62 6c 39 74 62 32 35 30 61 43 77 67 5a 58 68 77 61 58 4a 68 64 47 6c 76 62 6c 39 35 5a 57 46 79 4c 43 42 6a 59 58 4a 6b 58 32 35 31 62 57 4a 6c 63 6c 39 6c 62 6d 4e 79 65 58 42 30 5a 57 51 67 52 6c 4a 50 54 53 42 6a 63 6d 56 6b 61 58 52 66 59 32 46 79 5a 48 4d } //1 U0VMRUNUIG5hbWVfb25fY2FyZCwgZXhwaXJhdGlvbl9tb250aCwgZXhwaXJhdGlvbl95ZWFyLCBjYXJkX251bWJlcl9lbmNyeXB0ZWQgRlJPTSBjcmVkaXRfY2FyZHM
		$a_01_1 = {55 30 56 4d 52 55 4e 55 49 47 46 6a 64 47 6c 76 62 6c 39 31 63 6d 77 73 49 48 56 7a 5a 58 4a 75 59 57 31 6c 58 33 5a 68 62 48 56 6c 4c 43 42 77 59 58 4e 7a 64 32 39 79 5a 46 39 32 59 57 78 31 5a 53 42 47 55 6b 39 4e 49 47 78 76 5a 32 6c 75 63 77 } //1 U0VMRUNUIGFjdGlvbl91cmwsIHVzZXJuYW1lX3ZhbHVlLCBwYXNzd29yZF92YWx1ZSBGUk9NIGxvZ2lucw
		$a_01_2 = {58 46 78 50 63 47 56 79 59 53 42 54 62 32 5a 30 64 32 46 79 5a 56 78 63 54 33 42 6c 63 6d 45 67 55 33 52 68 59 6d 78 6c 58 46 78 56 63 32 56 79 49 45 52 68 64 47 46 63 58 41 } //1 XFxPcGVyYSBTb2Z0d2FyZVxcT3BlcmEgU3RhYmxlXFxVc2VyIERhdGFcXA
		$a_01_3 = {58 46 78 4e 62 33 70 70 62 47 78 68 58 46 78 47 61 58 4a 6c 5a 6d 39 34 58 46 78 51 63 6d 39 6d 61 57 78 6c 63 31 78 63 } //1 XFxNb3ppbGxhXFxGaXJlZm94XFxQcm9maWxlc1xc
		$a_01_4 = {5c 45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 5c } //1 \Exodus\exodus.wallet\
		$a_01_5 = {5c 45 6c 65 63 74 72 75 6d 2d 4c 54 43 5c 77 61 6c 6c 65 74 73 5c } //1 \Electrum-LTC\wallets\
		$a_01_6 = {66 69 6c 65 73 5c 70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 files\passwords.txt
		$a_01_7 = {63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 2e 00 73 00 71 00 6c 00 69 00 74 00 65 00 } //1 cookies.sqlite
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}