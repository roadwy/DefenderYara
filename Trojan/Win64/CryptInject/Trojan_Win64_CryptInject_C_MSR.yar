
rule Trojan_Win64_CryptInject_C_MSR{
	meta:
		description = "Trojan:Win64/CryptInject.C!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 41 64 6d 69 6e 44 65 6e 69 65 64 2e 76 62 73 } //1 start AdminDenied.vbs
		$a_01_1 = {68 71 64 65 66 61 75 6c 74 2e 6a 70 67 } //1 hqdefault.jpg
		$a_01_2 = {6f 62 6a 2e 44 65 6c 65 74 65 46 69 6c 65 28 22 2a 2e 76 62 73 22 29 } //1 obj.DeleteFile("*.vbs")
		$a_01_3 = {44 45 4c 20 2f 66 20 41 75 74 6f 52 75 6e 2e 62 61 74 } //1 DEL /f AutoRun.bat
		$a_01_4 = {64 65 6c 20 22 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 73 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 6c 6f 67 6f 66 66 2e 65 78 65 } //1 del "%userprofile%\AppData\Roaming\Microsoft\Windows\start Menu\Programs\Startup\logoff.exe
		$a_01_5 = {73 68 75 74 64 6f 77 6e 20 2d 4c } //1 shutdown -L
		$a_01_6 = {70 72 6f 67 72 61 6d 64 61 74 61 5c 73 73 68 5c 6c 6f 6f 70 31 2e 62 61 74 } //1 programdata\ssh\loop1.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}