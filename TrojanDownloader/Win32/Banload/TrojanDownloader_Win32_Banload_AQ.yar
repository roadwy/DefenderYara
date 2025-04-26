
rule TrojanDownloader_Win32_Banload_AQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQ,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {52 43 50 54 20 54 4f } //1 RCPT TO
		$a_01_2 = {4d 41 49 4c 20 46 52 4f 4d } //1 MAIL FROM
		$a_01_3 = {78 6f 6f 6d 65 72 2e 61 6c 69 63 65 2e 69 74 } //1 xoomer.alice.it
		$a_01_4 = {74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //1 terra.com.br
		$a_01_5 = {6c 6f 67 69 6e 2e 6c 69 76 65 2e 63 6f 6d 2f 70 70 73 65 63 75 72 65 2f 73 68 61 31 61 75 74 68 2e 73 72 66 } //1 login.live.com/ppsecure/sha1auth.srf
		$a_01_6 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_7 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
		$a_01_8 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}