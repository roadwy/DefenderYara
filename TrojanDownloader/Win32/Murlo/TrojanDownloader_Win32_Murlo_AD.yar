
rule TrojanDownloader_Win32_Murlo_AD{
	meta:
		description = "TrojanDownloader:Win32/Murlo.AD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {45 4a 77 61 4c 6f 61 64 4c 69 62 72 61 72 79 45 72 72 6f 72 } //1 EJwaLoadLibraryError
		$a_01_1 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_01_2 = {5c 5c 2e 5c 4c 75 6f 58 75 65 } //1 \\.\LuoXue
		$a_01_3 = {5c 64 72 69 76 65 72 73 5c 62 65 65 70 2e 73 79 73 } //1 \drivers\beep.sys
		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6a 6a 75 65 41 2e 65 78 65 } //1 C:\Program Files\jjueA.exe
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6a 6a 75 65 42 2e 65 78 65 } //1 C:\Program Files\jjueB.exe
		$a_01_6 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6a 6a 75 65 43 2e 65 78 65 } //1 C:\Program Files\jjueC.exe
		$a_01_7 = {4c 6f 76 65 48 65 62 65 } //1 LoveHebe
		$a_01_8 = {5c 58 75 65 2e 65 78 65 } //1 \Xue.exe
		$a_01_9 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 58 00 75 00 65 00 4c 00 75 00 6f 00 } //1 \Device\XueLuo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}