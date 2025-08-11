
rule Trojan_MacOS_PasivRobber_A_MTB{
	meta:
		description = "Trojan:MacOS/PasivRobber.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f b6 73 fe 48 89 f7 48 c1 ef 02 42 0f b6 0c 0f 41 88 4c 05 00 c1 e6 04 83 e6 30 0f b6 4b ff 48 89 cf 48 c1 ef 04 48 09 f7 41 0f b6 14 39 41 88 54 05 01 83 e1 0f 0f b6 13 48 89 d6 48 c1 ee 06 48 8d 0c 8e 41 0f b6 0c 09 41 88 4c 05 02 83 e2 3f 42 0f b6 0c 0a 41 88 4c 05 03 48 83 c0 04 48 83 c3 03 49 39 c0 } //1
		$a_01_1 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 58 8b 4e 30 85 c9 0f 8e 62 02 00 00 49 89 f7 48 8b 1a 48 8b 72 08 48 89 f7 b8 01 00 00 00 48 29 df 0f 84 49 02 00 00 48 89 55 80 45 31 f6 4c 89 7d c8 } //1
		$a_01_2 = {41 8b 4f 30 41 01 ce 48 8b 45 80 48 8b 18 48 8b 70 08 48 89 f7 48 29 df 4c 39 f7 0f 86 06 02 00 00 0f 57 c0 0f 29 45 a0 48 c7 45 b0 00 00 00 00 85 c9 } //1
		$a_01_3 = {54 42 4c 5f 41 46 5f 57 45 42 5f 51 51 42 52 4f 57 53 45 52 5f 44 4f 57 4e 4c 4f 41 44 } //1 TBL_AF_WEB_QQBROWSER_DOWNLOAD
		$a_01_4 = {54 42 4c 5f 41 46 5f 57 45 42 5f 4c 49 4e 55 58 5f 46 49 52 45 46 4f 58 5f 53 45 41 52 43 48 } //1 TBL_AF_WEB_LINUX_FIREFOX_SEARCH
		$a_01_5 = {54 42 4c 5f 41 46 5f 57 45 42 5f 43 48 52 4f 4d 45 5f 4c 4f 47 49 4e 5f 44 41 54 41 } //1 TBL_AF_WEB_CHROME_LOGIN_DATA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}