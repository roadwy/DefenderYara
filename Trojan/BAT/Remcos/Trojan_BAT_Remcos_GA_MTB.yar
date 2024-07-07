
rule Trojan_BAT_Remcos_GA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {2f 2f 31 30 37 2e 31 38 39 2e 34 2e 37 30 2f 36 39 33 2e 62 69 6e } //1 //107.189.4.70/693.bin
		$a_81_1 = {4a 69 6f 7a 2e 4e 65 77 46 69 6c 65 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 Jioz.NewFileForm.resources
		$a_81_2 = {4a 69 6f 7a 2e 50 72 6f 70 65 72 74 69 65 73 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 Jioz.PropertiesForm.resources
		$a_81_3 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //1 HttpWebResponse
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Trojan_BAT_Remcos_GA_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 41 64 64 49 6e 50 72 6f 63 65 73 73 33 32 2e 65 78 65 } //%systemroot%\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe  10
		$a_02_1 = {74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 90 02 14 2e 00 90 02 1e 2e 00 72 00 75 00 2f 00 90 02 28 90 0a 96 00 68 00 90 00 } //10
		$a_02_2 = {74 74 70 73 3a 2f 2f 90 02 14 2e 90 02 1e 2e 72 75 2f 90 02 28 90 0a 96 00 68 90 00 } //10
		$a_80_3 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //set_UseShellExecute  1
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  1
		$a_80_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_6 = {53 79 73 74 65 6d 4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c 6c } //SystemNetworkCredentiall  1
		$a_80_7 = {65 5f 6c 66 61 6e 65 77 } //e_lfanew  1
		$a_80_8 = {53 65 63 75 72 69 74 79 43 72 79 70 74 6f 67 72 61 70 68 79 43 41 50 49 42 61 73 65 43 45 52 54 } //SecurityCryptographyCAPIBaseCERT  1
		$a_80_9 = {4c 6f 63 61 74 69 6f 6e } //Location  1
	condition:
		((#a_80_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=26
 
}