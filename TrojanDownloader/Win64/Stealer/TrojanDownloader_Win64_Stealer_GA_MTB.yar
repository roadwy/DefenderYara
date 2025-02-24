
rule TrojanDownloader_Win64_Stealer_GA_MTB{
	meta:
		description = "TrojanDownloader:Win64/Stealer.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 } //1 powershell.exe -c Invoke-WebRequest -Uri
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 62 61 64 6c 61 72 72 79 73 67 75 69 74 61 72 73 2e 63 6f 6d } //1 https://badlarrysguitars.com
		$a_01_2 = {54 45 4d 50 3d 43 3a 5c 54 45 4d 50 } //1 TEMP=C:\TEMP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}