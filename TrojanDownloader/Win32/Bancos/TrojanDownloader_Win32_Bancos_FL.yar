
rule TrojanDownloader_Win32_Bancos_FL{
	meta:
		description = "TrojanDownloader:Win32/Bancos.FL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 70 72 6f 64 75 63 74 73 2f 65 72 72 6f 2e 70 68 70 } //1 /products/erro.php
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4e 69 63 72 6f 73 6f 66 74 2e 65 78 65 } //1 Software\Classes\Applications\Nicrosoft.exe
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4e 61 74 47 61 74 5f 2e 65 78 65 } //1 Software\Classes\Applications\NatGat_.exe
		$a_01_3 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_01_4 = {44 6f 6e 74 52 65 70 6f 72 74 49 6e 66 65 63 74 69 6f 6e 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 DontReportInfectionInformation
		$a_01_5 = {41 74 75 61 6c 69 7a 61 e7 e3 6f 20 64 6f 20 57 69 6e 64 6f 77 73 20 63 6f 6d 70 6c 65 74 61 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}