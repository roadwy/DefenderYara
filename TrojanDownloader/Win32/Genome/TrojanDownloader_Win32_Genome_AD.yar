
rule TrojanDownloader_Win32_Genome_AD{
	meta:
		description = "TrojanDownloader:Win32/Genome.AD,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 6f 66 66 69 63 65 73 75 70 64 61 74 65 2e 63 6f 6d 2f 75 70 64 61 74 65 2e 69 6e 69 } //1 .officesupdate.com/update.ini
		$a_01_1 = {2e 67 6f 6f 6e 6d 61 78 2e 63 6e 2f 75 70 64 61 74 65 2e 69 6e 69 } //1 .goonmax.cn/update.ini
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 2f 25 73 25 78 26 76 65 72 73 69 6f 6e 3d 25 64 26 73 74 63 3d } //2 http://%s/%s%x&version=%d&stc=
		$a_01_3 = {73 6e 6f 77 68 74 6d 6c 2e 74 78 74 } //2 snowhtml.txt
		$a_01_4 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 63 6f 6d 6c 6d 64 73 2e 6c 6f 67 } //2 c:\windows\comlmds.log
		$a_01_5 = {61 31 2e 65 78 65 } //2 a1.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=8
 
}