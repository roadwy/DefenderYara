
rule TrojanDropper_Win64_XMRig_CM_MTB{
	meta:
		description = "TrojanDropper:Win64/XMRig.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 63 68 6f 20 46 69 6c 65 20 64 65 6c 65 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //2 echo File deleted successfully.
		$a_01_1 = {64 65 6c 20 22 25 7e 66 30 22 } //2 del "%~f0"
		$a_01_2 = {64 65 6c 65 74 65 5f 73 65 6c 66 2e 62 61 74 } //2 delete_self.bat
		$a_01_3 = {2f 00 71 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 25 00 77 00 69 00 6e 00 64 00 69 00 72 00 25 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 5f 00 20 00 26 00 20 00 5f 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //2 /q /c start %windir%\explorer _ & _\explorer.exe
		$a_01_4 = {6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 20 00 2e 00 64 00 6c 00 6c 00 } //2 kernel32 .dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}