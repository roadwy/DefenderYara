
rule Trojan_BAT_SmallDownloader_RK_MTB{
	meta:
		description = "Trojan:BAT/SmallDownloader.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 31 30 30 74 68 72 65 61 64 73 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 74 65 73 74 2e 74 78 74 } //1 https://100threads.000webhostapp.com/test.txt
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 41 64 72 69 61 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 55 70 64 61 74 65 72 50 72 6f 5c 55 70 64 61 74 65 72 50 72 6f 5c 6f 62 6a 5c 44 65 62 75 67 5c 55 70 64 61 74 65 72 50 72 6f 2e 70 64 62 } //1 C:\Users\Adrian\source\repos\UpdaterPro\UpdaterPro\obj\Debug\UpdaterPro.pdb
		$a_01_2 = {63 6d 64 2e 65 78 65 } //1 cmd.exe
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_4 = {55 70 64 61 74 65 72 50 72 6f } //1 UpdaterPro
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}