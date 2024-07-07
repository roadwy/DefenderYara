
rule Trojan_BAT_Stealer_NB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 77 69 74 63 68 2d 53 74 65 61 6c 65 72 } //2 Switch-Stealer
		$a_81_1 = {59 6f 75 54 75 62 65 2d 6d 61 69 6e 20 44 65 6c 74 61 20 76 39 32 20 72 6f 6c 6c 23 31 } //2 YouTube-main Delta v92 roll#1
		$a_81_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 63 66 67 2e 65 78 65 } //2 AppData\Local\Temp\cfg.exe
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //2 DownloadString
		$a_81_4 = {73 65 74 5f 53 74 61 72 74 75 70 55 72 69 } //1 set_StartupUri
		$a_81_5 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } //1 DownloadFileAsync
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=10
 
}