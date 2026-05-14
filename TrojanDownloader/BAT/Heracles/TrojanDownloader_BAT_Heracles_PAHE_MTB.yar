
rule TrojanDownloader_BAT_Heracles_PAHE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.PAHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 00 6f 00 62 00 72 00 69 00 6b 00 2e 00 70 00 73 00 31 00 } //1 bobrik.ps1
		$a_01_1 = {52 65 6d 6f 76 65 2d 49 74 65 6d 20 43 3a 5c 2a 20 2d 52 65 63 75 72 73 65 20 2d 46 6f 72 63 65 } //1 Remove-Item C:\* -Recurse -Force
		$a_03_2 = {49 6e 76 6f 6b 65 2d 52 65 73 74 4d 65 74 68 6f 64 20 2d 55 72 69 20 22 68 74 74 [0-02] 3a 2f 2f 77 74 74 72 2e 69 6e 2f 24 43 69 74 79 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}