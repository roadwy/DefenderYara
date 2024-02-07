
rule Trojan_BAT_Downloader_CAJ_MTB{
	meta:
		description = "Trojan:BAT/Downloader.CAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 36 35 34 30 38 65 39 61 2d 64 30 34 35 2d 34 36 36 38 2d 62 66 31 34 2d 65 65 30 39 36 35 36 66 38 36 35 66 } //01 00  $65408e9a-d045-4668-bf14-ee09656f865f
		$a_81_1 = {50 6c 65 61 73 65 20 64 69 73 61 62 6c 65 20 74 68 65 20 74 68 69 72 64 2d 70 61 72 74 79 20 61 6e 74 69 76 69 72 75 73 2c 20 69 74 20 6d 61 79 20 70 72 65 76 65 6e 74 20 74 6f 20 6f 75 72 20 69 6e 6a 65 63 74 69 6f 6e 20 6d 65 74 68 6f 64 } //01 00  Please disable the third-party antivirus, it may prevent to our injection method
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 73 65 63 75 72 65 2e 65 69 63 61 72 2e 6f 72 67 2f 65 69 63 61 72 2e 63 6f 6d } //01 00  https://secure.eicar.org/eicar.com
		$a_81_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 65 69 63 61 72 2e 63 6f 6d } //01 00  C:\ProgramData\eicar.com
		$a_81_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 50 72 6f 67 72 61 6d 46 69 6c 65 73 28 78 38 36 29 5c 74 65 73 74 69 6b 32 2e 65 78 65 } //01 00  C:\ProgramData\ProgramFiles(x86)\testik2.exe
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //00 00  DownloadFile
	condition:
		any of ($a_*)
 
}