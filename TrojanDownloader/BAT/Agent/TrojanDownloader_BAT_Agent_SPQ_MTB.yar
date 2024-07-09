
rule TrojanDownloader_BAT_Agent_SPQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Agent.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {11 04 08 1f 1a 28 ?? ?? ?? 0a 72 81 00 00 70 09 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 1f 1a 28 ?? ?? ?? 0a 72 37 00 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 de 0e } //2
		$a_81_1 = {55 73 65 72 73 5c 4e 69 73 68 61 5c 44 65 73 6b 74 6f 70 5c 43 72 61 63 6b 65 64 20 50 61 73 74 65 42 69 6e 20 2d 20 31 33 33 37 5c 43 72 61 63 6b 65 64 20 50 61 73 74 65 42 69 6e 5c 6f 62 6a 5c 44 65 62 75 67 5c 53 65 74 75 70 2e 70 64 62 } //1 Users\Nisha\Desktop\Cracked PasteBin - 1337\Cracked PasteBin\obj\Debug\Setup.pdb
		$a_81_2 = {43 72 61 63 6b 65 64 5f 50 61 73 74 65 42 69 6e 2e 4d 79 } //1 Cracked_PasteBin.My
		$a_01_3 = {43 00 72 00 61 00 63 00 6b 00 65 00 64 00 5f 00 50 00 61 00 73 00 74 00 65 00 42 00 69 00 6e 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Cracked_PasteBin.Resources
		$a_01_4 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //1 WindowsServices\WindowsServices.exe
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}