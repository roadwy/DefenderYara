
rule Trojan_BAT_Bladabindi_SBR_MSR{
	meta:
		description = "Trojan:BAT/Bladabindi.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 cf 00 00 70 7e 08 00 00 04 6f ?? 00 00 0a 72 13 01 00 70 28 ?? 00 00 0a 16 16 15 28 ?? 00 00 0a 26 de 03 } //1
		$a_03_1 = {11 05 12 06 28 ?? 00 00 06 13 07 11 07 28 ?? 00 00 06 28 ?? 00 00 0a 13 08 02 09 07 06 1b 16 11 08 28 ?? 00 00 06 26 06 6f ?? 00 00 0a 0c 08 13 09 de 10 } //1
		$a_01_2 = {54 00 6c 00 6c 00 42 00 54 00 69 00 42 00 44 00 51 00 56 00 51 00 3d 00 } //1 TllBTiBDQVQ=
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_Bladabindi_SBR_MSR_2{
	meta:
		description = "Trojan:BAT/Bladabindi.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 65 72 20 62 6c 61 63 6b 20 63 61 74 20 73 65 6d 69 20 66 75 64 20 3d 20 75 73 61 72 20 65 73 73 65 20 3d 20 66 69 6e 61 6c 5c 73 6f 66 74 77 61 72 65 2e 70 64 62 } //1 crypter black cat semi fud = usar esse = final\software.pdb
		$a_01_1 = {53 6f 66 74 77 61 72 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Software.Resources.resources
		$a_01_2 = {23 42 77 2e 23 54 68 2e 72 65 73 6f 75 72 63 65 73 } //1 #Bw.#Th.resources
		$a_01_3 = {43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 2e 00 52 00 69 00 6a 00 6e 00 64 00 61 00 65 00 6c 00 4d 00 61 00 6e 00 61 00 67 00 65 00 64 00 } //1 Cryptography.RijndaelManaged
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_BAT_Bladabindi_SBR_MSR_3{
	meta:
		description = "Trojan:BAT/Bladabindi.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 34 00 35 00 2e 00 31 00 33 00 38 00 2e 00 31 00 37 00 32 00 2e 00 31 00 35 00 38 00 } //5 http://45.138.172.158
		$a_01_1 = {4c 00 69 00 67 00 68 00 74 00 73 00 68 00 6f 00 74 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Lightshotinstaller.Properties.Resources
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 53 61 76 65 72 } //1 DownloadToFileSaver
		$a_01_3 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 Select * from Win32_ComputerSystem
		$a_01_4 = {48 00 6f 00 73 00 74 00 5c 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 Host\host.exe
		$a_01_5 = {74 00 6f 00 71 00 65 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 62 00 75 00 73 00 69 00 6e 00 65 00 73 00 73 00 } //1 toqe.downloader.business
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}