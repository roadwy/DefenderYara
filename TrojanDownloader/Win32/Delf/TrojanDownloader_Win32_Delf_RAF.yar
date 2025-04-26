
rule TrojanDownloader_Win32_Delf_RAF{
	meta:
		description = "TrojanDownloader:Win32/Delf.RAF,SIGNATURE_TYPE_PEHSTR,05 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {4b 75 6f 44 6f 75 53 65 74 75 70 2e 65 78 65 } //1 KuoDouSetup.exe
		$a_01_1 = {2e 78 7a 31 39 2e 63 6f 6d 3a 32 31 30 30 30 2f 61 76 74 76 2f } //1 .xz19.com:21000/avtv/
		$a_01_2 = {2f 6d 79 69 65 2f 43 6e 4e 75 6f 49 45 2e 65 78 65 } //1 /myie/CnNuoIE.exe
		$a_01_3 = {2f 79 78 6b 75 2f 73 65 74 75 70 73 2e 65 78 65 } //1 /yxku/setups.exe
		$a_01_4 = {2e 64 6f 77 6e 2e 78 7a 31 39 2e 63 6f 6d 3a 32 31 30 30 30 2f 62 61 63 6b 75 70 2f } //1 .down.xz19.com:21000/backup/
		$a_01_5 = {63 2e 6a 66 35 32 2e 63 6f 6d 2f 63 6f 64 65 2f 4c 4c 5f 63 6f 75 6e 74 2e 61 73 70 } //1 c.jf52.com/code/LL_count.asp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}