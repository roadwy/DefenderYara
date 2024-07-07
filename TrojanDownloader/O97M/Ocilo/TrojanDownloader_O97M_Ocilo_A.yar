
rule TrojanDownloader_O97M_Ocilo_A{
	meta:
		description = "TrojanDownloader:O97M/Ocilo.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 90 01 14 2e 62 61 74 22 90 00 } //1
		$a_00_1 = {66 43 68 65 63 6b 2e 46 69 6c 65 45 78 69 73 74 73 28 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 4d 53 42 75 69 6c 64 2e 65 78 65 22 29 } //1 fCheck.FileExists("C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe")
		$a_02_2 = {43 61 6c 6c 20 53 68 65 6c 6c 28 90 01 14 2c 20 76 62 48 69 64 65 29 90 00 } //1
		$a_02_3 = {45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 90 01 14 2e 74 78 74 22 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}