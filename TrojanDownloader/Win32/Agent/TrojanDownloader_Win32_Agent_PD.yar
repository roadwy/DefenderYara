
rule TrojanDownloader_Win32_Agent_PD{
	meta:
		description = "TrojanDownloader:Win32/Agent.PD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 74 61 74 2e 77 61 6d 6d 65 2e 63 6e 2f 43 38 43 2f 67 6c 2f 63 6e 7a 7a 36 30 2e 68 74 6d 6c } //1 http://stat.wamme.cn/C8C/gl/cnzz60.html
		$a_01_1 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 73 65 72 76 69 63 65 32 2e 69 6e 69 } //1 system32\drivers\etc\service2.ini
		$a_01_2 = {68 00 b6 32 01 f3 a5 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}