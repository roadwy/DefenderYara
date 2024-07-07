
rule TrojanDownloader_Win32_Renos_IF{
	meta:
		description = "TrojanDownloader:Win32/Renos.IF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_03_0 = {68 a0 bb 0d 00 6a 00 6a 00 a3 90 01 04 ff d6 68 90 01 02 00 10 68 e8 03 00 00 6a 00 6a 00 ff d6 68 90 01 02 00 10 68 e0 93 04 00 6a 00 6a 00 ff d6 68 90 01 02 00 10 68 00 f9 15 00 90 00 } //5
		$a_01_1 = {64 69 73 74 75 72 62 20 79 6f 75 20 65 76 65 6e 20 77 68 65 6e 20 79 6f 75 72 65 20 6e 6f 74 20 73 75 72 66 69 6e 67 20 74 68 65 20 49 6e 74 65 72 6e 65 74 2e } //1 disturb you even when youre not surfing the Internet.
		$a_01_2 = {53 70 79 77 61 72 65 20 63 61 6e 20 6e 6f 74 20 62 65 20 72 65 6d 6f 76 65 64 20 62 79 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 20 61 6e 64 20 66 69 72 65 77 61 6c 6c 73 } //1 Spyware can not be removed by antivirus software and firewalls
		$a_01_3 = {74 68 65 20 63 6f 6d 70 75 74 65 72 20 69 73 20 69 6e 20 72 69 73 6b 20 6f 66 20 62 65 69 6e 67 20 63 6f 6e 74 61 6d 69 6e 61 74 65 64 20 77 69 74 68 20 6d 61 6c 69 63 69 6f 75 73 } //1 the computer is in risk of being contaminated with malicious
		$a_01_4 = {76 75 6c 6e 65 72 61 62 6c 65 20 74 6f 20 62 65 20 69 6e 74 65 72 66 65 72 65 64 20 62 79 20 70 65 6f 70 6c 65 20 77 68 6f 20 77 61 6e 74 73 20 74 6f 20 73 74 65 61 6c 20 79 6f 75 72 20 70 72 69 76 61 74 65 } //1 vulnerable to be interfered by people who wants to steal your private
		$a_01_5 = {68 69 67 68 20 70 72 6f 62 61 62 69 6c 69 74 79 20 74 68 61 74 20 79 6f 75 72 20 69 73 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 6d 61 6c 69 63 69 6f 75 73 20 73 70 79 77 } //1 high probability that your is infected with malicious spyw
		$a_03_6 = {5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 90 02 04 20 22 90 02 04 22 2c 20 73 74 61 72 74 90 00 } //1
		$a_01_7 = {70 6d 75 74 65 78 5f 25 64 } //1 pmutex_%d
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}