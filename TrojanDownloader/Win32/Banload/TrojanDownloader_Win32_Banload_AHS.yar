
rule TrojanDownloader_Win32_Banload_AHS{
	meta:
		description = "TrojanDownloader:Win32/Banload.AHS,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 63 44 6f 50 4d 35 71 50 47 } //2 BcDoPM5qPG
		$a_01_1 = {46 33 6e 6b 52 73 72 62 46 5a 75 } //2 F3nkRsrbFZu
		$a_01_2 = {46 33 6e 5a 4f 4d 72 66 52 63 58 6c 46 5a 75 } //2 F3nZOMrfRcXlFZu
		$a_01_3 = {49 4d 76 71 50 4e 39 6b 50 4e 47 57 48 4e 58 6d 52 36 7a 6f 50 4e 39 56 4b 73 4c 6f 54 63 4c 6f } //1 IMvqPN9kPNGWHNXmR6zoPN9VKsLoTcLo
		$a_01_4 = {51 36 7a 71 52 4d 35 66 52 30 } //1 Q6zqRM5fR0
		$a_01_5 = {50 4d 76 71 53 63 35 6f } //1 PMvqSc5o
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}