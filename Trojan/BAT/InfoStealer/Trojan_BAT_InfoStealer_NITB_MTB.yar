
rule Trojan_BAT_InfoStealer_NITB_MTB{
	meta:
		description = "Trojan:BAT/InfoStealer.NITB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {00 00 72 c1 0e 00 70 28 ?? 00 00 0a 0a 16 0b 2b 21 06 07 9a 0c 00 00 08 6f 62 00 00 0a 00 08 6f 37 00 00 0a 00 00 de 05 0d 00 00 de 00 00 07 17 58 0b 07 06 8e 69 32 d9 } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 44 65 63 6f 64 65 46 69 6c 65 41 73 79 6e 63 } //1 DownloadAndDecodeFileAsync
		$a_01_2 = {69 73 4f 70 65 72 61 47 58 6f 72 46 69 72 65 66 6f 78 } //1 isOperaGXorFirefox
		$a_01_3 = {44 65 63 72 79 70 74 41 6e 64 57 72 69 74 65 46 69 72 65 66 6f 78 44 61 74 61 } //1 DecryptAndWriteFirefoxData
		$a_01_4 = {4b 69 6c 6c 45 78 69 73 74 69 6e 67 54 6f 72 50 72 6f 63 65 73 73 65 73 } //1 KillExistingTorProcesses
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}