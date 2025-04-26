
rule Trojan_Win32_Dumaru{
	meta:
		description = "Trojan:Win32/Dumaru,SIGNATURE_TYPE_PEHSTR,08 00 05 00 0c 00 00 "
		
	strings :
		$a_01_0 = {31 39 39 2e 31 36 36 2e 36 2e 32 } //2 199.166.6.2
		$a_01_1 = {2a 2a 2a 20 50 72 6f 74 65 63 74 65 64 20 53 74 6f 72 61 67 65 20 44 61 74 61 20 2a 2a 2a } //1 *** Protected Storage Data ***
		$a_01_2 = {2a 2a 2a 20 50 72 6f 74 65 63 74 65 64 20 53 74 6f 72 61 67 65 20 44 61 74 61 20 65 6e 64 73 20 2a 2a 2a } //1 *** Protected Storage Data ends ***
		$a_01_3 = {3c 61 64 64 72 65 73 73 40 79 61 6e 64 65 78 2e 72 75 3e } //2 <address@yandex.ru>
		$a_01_4 = {3d 3d 3d 4b 45 59 4c 4f 47 47 45 52 20 44 41 54 41 20 45 4e 44 3d 3d 3d } //1 ===KEYLOGGER DATA END===
		$a_01_5 = {3d 3d 3d 4b 45 59 4c 4f 47 47 45 52 20 44 41 54 41 20 53 54 41 52 54 3d 3d 3d } //1 ===KEYLOGGER DATA START===
		$a_01_6 = {5c 72 75 6e 64 6c 6c 78 2e 73 79 73 } //1 \rundllx.sys
		$a_01_7 = {5c 72 75 6e 64 6c 6c 6e 2e 73 79 73 } //1 \rundlln.sys
		$a_01_8 = {5c 76 78 64 6c 6f 61 64 2e 6c 6f 67 } //1 \vxdload.log
		$a_01_9 = {5c 54 45 4d 50 5c 31 2e 65 6d 6c } //1 \TEMP\1.eml
		$a_01_10 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 5c 6c 6f 61 64 33 32 2e 65 78 65 } //2 C:\WINDOWS\SYSTEM\load32.exe
		$a_01_11 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 5c 76 78 64 6d 67 72 33 32 2e 65 78 65 } //2 explorer.exe C:\WINDOWS\SYSTEM\vxdmgr32.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2) >=5
 
}