
rule Trojan_Win32_CryptInject_GDT_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.GDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_01_0 = {8b ca 8b f2 83 e1 1f 33 f0 d3 ce 3b f7 74 69 85 f6 74 04 } //10
		$a_02_1 = {8b c1 83 e1 3f c1 f8 06 6b c9 30 8b 04 85 ?? ?? ?? ?? f6 44 08 28 01 74 06 } //10
		$a_80_2 = {6f 6e 74 64 6c 6c 2e 64 6c 6c } //ontdll.dll  1
		$a_80_3 = {65 71 75 69 63 6b 73 65 65 69 6e 73 74 2e 65 78 65 } //equickseeinst.exe  1
		$a_80_4 = {71 75 69 63 6b 73 65 65 69 6e 73 74 2e 64 6c 6c } //quickseeinst.dll  1
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //1 URLDownloadToFile
		$a_01_6 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_01_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
		$a_01_8 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
	condition:
		((#a_01_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=27
 
}