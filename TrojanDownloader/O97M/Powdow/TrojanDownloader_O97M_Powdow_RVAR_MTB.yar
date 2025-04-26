
rule TrojanDownloader_O97M_Powdow_RVAR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 61 63 68 2d 65 64 69 2e 78 79 7a 2f 72 65 6d 69 74 2f 6d 61 69 6c 2e 65 78 65 22 } //5 ://ach-edi.xyz/remit/mail.exe"
		$a_01_1 = {3a 2f 2f 33 34 2e 32 35 35 2e 32 31 37 2e 37 30 2f 70 75 74 74 79 2e 65 78 65 22 } //5 ://34.255.217.70/putty.exe"
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 63 6d 64 4c 69 6e 65 2c 20 30 } //1 CreateObject("WScript.Shell").Run cmdLine, 0
		$a_01_3 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 6d 79 55 52 4c 2c 20 46 61 6c 73 65 20 27 2c 20 22 75 73 65 72 6e 61 6d 65 22 2c 20 22 70 61 73 73 77 6f 72 64 22 } //1 .Open "GET", myURL, False ', "username", "password"
		$a_01_4 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 0d 0a 20 20 20 20 44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}