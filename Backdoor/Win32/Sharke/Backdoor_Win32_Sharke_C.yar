
rule Backdoor_Win32_Sharke_C{
	meta:
		description = "Backdoor:Win32/Sharke.C,SIGNATURE_TYPE_PEHSTR,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {77 00 77 00 77 00 2e 00 73 00 68 00 61 00 72 00 6b 00 2d 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 2e 00 6e 00 65 00 74 00 } //1 www.shark-project.net
		$a_01_1 = {48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c 00 } //1 HKCU\Software\Microsoft\Windows\CurrentVersion\Run\
		$a_01_2 = {5c 00 73 00 68 00 61 00 72 00 4b 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 5c 00 } //1 \sharK\Server\
		$a_01_3 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //1 \system32\drivers\etc\hosts
		$a_01_4 = {53 00 63 00 72 00 69 00 70 00 74 00 69 00 6e 00 67 00 2e 00 46 00 69 00 6c 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //1 Scripting.FileSystemObject
		$a_01_5 = {2a 00 6d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 2e 00 73 00 68 00 61 00 72 00 6b 00 } //1 *messenger.shark
		$a_01_6 = {69 00 61 00 6d 00 61 00 73 00 68 00 61 00 72 00 6b 00 70 00 6c 00 75 00 67 00 69 00 6e 00 } //1 iamasharkplugin
		$a_01_7 = {2a 00 70 00 73 00 74 00 6f 00 72 00 61 00 67 00 65 00 2e 00 73 00 68 00 61 00 72 00 6b 00 } //1 *pstorage.shark
		$a_01_8 = {43 00 3a 00 5c 00 73 00 68 00 61 00 72 00 6b 00 2e 00 75 00 70 00 64 00 61 00 74 00 65 00 } //1 C:\shark.update
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}