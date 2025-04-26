
rule Trojan_BAT_CoinMiner_SB_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 } //api.telegram.org/bot  1
		$a_80_1 = {61 70 69 2e 69 70 69 66 79 2e 6f 72 67 } //api.ipify.org  1
		$a_80_2 = {35 31 2e 37 35 2e 33 36 2e 31 38 34 } //51.75.36.184  1
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_80_4 = {73 63 68 74 61 73 6b 73 2e 65 78 65 } //schtasks.exe  1
		$a_80_5 = {2f 63 72 65 61 74 65 20 2f 73 63 20 4d 49 4e 55 54 45 20 2f 6d 6f 20 31 20 2f 74 6e } ///create /sc MINUTE /mo 1 /tn  1
		$a_01_6 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_80_7 = {5c 57 69 6e 64 6f 77 73 20 46 6f 6c 64 65 72 } //\Windows Folder  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_01_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}