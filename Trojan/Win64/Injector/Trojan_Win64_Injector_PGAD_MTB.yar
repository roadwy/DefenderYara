
rule Trojan_Win64_Injector_PGAD_MTB{
	meta:
		description = "Trojan:Win64/Injector.PGAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 69 6e 6a 65 63 74 6f 72 2e 64 6c 6c } //1 \injector.dll
		$a_01_1 = {2f 2f 31 30 2e 31 34 38 2e 30 2e 38 3a 38 30 30 30 2f 69 6e 6a 65 63 74 6f 72 2e 62 69 6e } //1 //10.148.0.8:8000/injector.bin
		$a_01_2 = {77 69 6e 5f 75 70 64 61 74 65 5f 73 65 72 76 69 63 65 2e 65 78 65 } //1 win_update_service.exe
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 75 72 6c 20 2d 73 20 2d 4c 20 22 } //1 cmd.exe /c curl -s -L "
		$a_03_4 = {44 4c 4c 20 49 4e 4a 45 43 54 49 4f 4e 20 53 55 43 43 45 53 53 46 [0-03] 4c 4c 59 21 } //1
		$a_01_5 = {6c 6f 67 2e 74 78 74 } //1 log.txt
		$a_01_6 = {6e 6f 74 65 70 61 64 2e 65 78 65 } //1 notepad.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_Win64_Injector_PGAD_MTB_2{
	meta:
		description = "Trojan:Win64/Injector.PGAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 5c 42 6f 6f 74 5c 6d 65 6d 74 65 73 74 2e 65 78 65 } //1 C:\\Boot\memtest.exe
		$a_01_1 = {46 75 6c 6c 20 44 65 6c 70 68 69 20 56 69 72 75 73 2f 57 6f 72 6d 20 6d 61 64 65 20 42 79 20 46 75 54 75 52 61 58 } //1 Full Delphi Virus/Worm made By FuTuRaX
		$a_01_2 = {43 3a 5c 5c 42 61 74 30 30 31 30 30 2e 62 61 74 } //1 C:\\Bat00100.bat
		$a_01_3 = {46 41 43 45 48 41 43 4b 45 52 } //1 FACEHACKER
		$a_01_4 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //1 software\microsoft\windows\currentversion\run
		$a_01_5 = {43 3a 5c 5c 57 49 4e 44 4f 57 53 5c 53 65 72 76 69 63 65 50 61 63 6b 46 69 6c 65 73 5c 69 33 38 36 5c 6c 61 6e 67 5c 74 69 6e 74 73 65 74 70 2e 65 78 65 } //1 C:\\WINDOWS\ServicePackFiles\i386\lang\tintsetp.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}