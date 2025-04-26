
rule TrojanDownloader_Win32_Mahost_A{
	meta:
		description = "TrojanDownloader:Win32/Mahost.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 20 6d 61 6a 2e 65 78 65 } //1 get maj.exe
		$a_01_1 = {50 61 72 63 6f 75 72 73 20 64 65 } //1 Parcours de
		$a_01_2 = {25 73 66 74 70 2e 74 78 74 } //1 %sftp.txt
		$a_01_3 = {66 74 70 20 2d 73 3a 22 25 73 } //1 ftp -s:"%s
		$a_01_4 = {4c 65 20 66 69 63 68 69 65 72 20 74 61 73 6b 68 6f 73 74 2e 65 78 65 20 76 69 65 6e 74 20 64 27 } //1 Le fichier taskhost.exe vient d'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}