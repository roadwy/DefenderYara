
rule Worm_Win32_Respup_A{
	meta:
		description = "Worm:Win32/Respup.A,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {57 6f 72 6d 2f 42 72 6f 6e 63 6f 2e 56 41 58 } //1 Worm/Bronco.VAX
		$a_01_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42 } //1 C:\Program Files\Microsoft Visual Studio\VB98\VB6.OLB
		$a_01_3 = {43 00 3a 00 5c 00 50 00 52 00 4f 00 47 00 52 00 41 00 7e 00 31 00 5c 00 4d 00 49 00 43 00 52 00 4f 00 53 00 7e 00 34 00 5c 00 56 00 42 00 39 00 38 00 5c 00 50 00 55 00 50 00 53 00 52 00 45 00 2e 00 76 00 62 00 70 00 } //1 C:\PROGRA~1\MICROS~4\VB98\PUPSRE.vbp
		$a_01_4 = {53 00 63 00 72 00 69 00 70 00 74 00 69 00 6e 00 67 00 2e 00 46 00 69 00 6c 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //1 Scripting.FileSystemObject
		$a_01_5 = {67 00 65 00 74 00 64 00 72 00 69 00 76 00 65 00 } //1 getdrive
		$a_01_6 = {50 00 55 00 50 00 53 00 52 00 45 00 2e 00 65 00 78 00 65 00 } //1 PUPSRE.exe
		$a_01_7 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_8 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 69 00 6e 00 66 00 5c 00 73 00 73 00 76 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 C:\WINDOWS\inf\ssvhost.exe
		$a_01_9 = {4d 00 79 00 20 00 50 00 69 00 63 00 74 00 75 00 72 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //1 My Pictures.exe
		$a_01_10 = {4d 00 79 00 20 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 2e 00 65 00 78 00 65 00 } //1 My Documents.exe
		$a_01_11 = {44 00 72 00 69 00 76 00 65 00 20 00 46 00 3a 00 5c 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 } //1 Drive F:\ infected
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}