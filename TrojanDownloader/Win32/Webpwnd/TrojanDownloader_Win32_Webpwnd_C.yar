
rule TrojanDownloader_Win32_Webpwnd_C{
	meta:
		description = "TrojanDownloader:Win32/Webpwnd.C,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {60 6a 30 59 64 8b 29 8b 45 0c 8b 70 1c ad 8b 68 08 8b 75 3c 8b 74 2e 78 03 f5 56 8b 76 20 03 f5 33 c9 49 41 ad 03 c5 33 db 0f be 10 3a d6 74 08 c1 cb 07 03 da 40 eb f1 81 fb 67 59 de 1e 75 e3 5e 8b 5e 24 03 dd 66 8b 0c 4b 8b 5e 1c 03 dd 8b 04 8b 03 c5 bf 00 08 00 00 6a 40 68 00 10 00 00 57 6a 00 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}