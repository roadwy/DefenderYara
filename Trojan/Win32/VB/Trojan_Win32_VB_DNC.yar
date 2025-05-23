
rule Trojan_Win32_VB_DNC{
	meta:
		description = "Trojan:Win32/VB.DNC,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0d 00 00 "
		
	strings :
		$a_00_0 = {77 78 72 22 22 2f 70 } //10 wxr""/p
		$a_00_1 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //10 OpenProcessToken
		$a_01_2 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //10 MSVBVM60.DLL
		$a_00_3 = {63 00 64 00 20 00 25 00 77 00 69 00 6e 00 64 00 69 00 72 00 25 00 26 00 72 00 65 00 61 00 64 00 65 00 64 00 2e 00 62 00 61 00 74 00 } //10 cd %windir%&readed.bat
		$a_00_4 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 20 00 2f 00 69 00 20 00 53 00 48 00 44 00 4f 00 43 00 56 00 57 00 2e 00 44 00 4c 00 4c 00 } //10 cmd.exe /c regsvr32 /s /i SHDOCVW.DLL
		$a_00_5 = {43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 2d 00 54 00 79 00 70 00 65 00 3a 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 78 00 2d 00 77 00 77 00 77 00 2d 00 66 00 6f 00 72 00 6d 00 2d 00 75 00 72 00 6c 00 65 00 6e 00 63 00 6f 00 64 00 65 00 64 00 } //10 Content-Type: application/x-www-form-urlencoded
		$a_00_6 = {5c 00 41 00 4c 00 4c 00 52 00 4f 00 55 00 4e 00 44 00 20 00 53 00 54 00 45 00 41 00 4c 00 45 00 52 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //10 \ALLROUND STEALER\Project1.vbp
		$a_00_7 = {63 00 6d 00 64 00 20 00 2f 00 63 00 } //1 cmd /c
		$a_00_8 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 2f 00 } //1 http:///
		$a_00_9 = {70 00 6f 00 73 00 74 00 3d 00 } //1 post=
		$a_00_10 = {52 00 45 00 4d 00 4f 00 54 00 45 00 20 00 44 00 52 00 49 00 56 00 45 00 } //1 REMOTE DRIVE
		$a_00_11 = {49 00 50 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 65 00 73 00 20 00 66 00 6f 00 75 00 6e 00 64 00 20 00 6f 00 6e 00 20 00 50 00 43 00 } //1 IP addresses found on PC
		$a_00_12 = {42 00 72 00 6f 00 61 00 64 00 43 00 61 00 73 00 74 00 20 00 49 00 50 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 } //1 BroadCast IP address
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=74
 
}