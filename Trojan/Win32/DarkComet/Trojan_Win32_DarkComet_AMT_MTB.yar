
rule Trojan_Win32_DarkComet_AMT_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0d 00 00 "
		
	strings :
		$a_01_0 = {57 41 52 4e 49 4e 47 20 2d 20 4d 41 4c 57 41 52 45 } //1 WARNING - MALWARE
		$a_01_1 = {54 68 69 73 20 69 73 20 63 6f 6e 73 69 64 65 72 65 64 20 4d 61 6c 77 61 72 65 } //1 This is considered Malware
		$a_01_2 = {49 66 20 79 6f 75 20 72 75 6e 20 69 74 2c 20 69 74 20 63 61 6e 20 6d 61 79 62 65 20 62 72 65 61 6b 20 79 6f 75 72 20 50 43 } //1 If you run it, it can maybe break your PC
		$a_01_3 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 } //1 Are you sure you want to continue
		$a_01_4 = {46 49 4e 41 4c 20 57 41 52 4e 49 4e 47 20 2d 20 59 4f 55 20 43 41 4e 54 20 47 4f 20 42 41 43 4b } //1 FINAL WARNING - YOU CANT GO BACK
		$a_01_5 = {54 68 69 73 20 57 69 6c 6c 20 46 6c 61 73 68 20 47 44 49 2c 20 50 6c 61 79 20 6c 6f 75 64 20 73 6f 75 6e 64 73 20 61 6e 64 20 6c 61 75 6e 63 68 20 50 61 79 6c 6f 61 64 73 } //2 This Will Flash GDI, Play loud sounds and launch Payloads
		$a_01_6 = {4e 6f 74 20 46 6f 72 20 45 70 69 6c 65 70 74 69 63 } //1 Not For Epileptic
		$a_01_7 = {44 4f 4e 54 20 52 55 4e 20 49 46 20 59 4f 55 20 44 4f 4e 54 20 4b 4e 4f 57 20 57 48 41 54 20 59 4f 55 27 52 45 20 44 4f 49 4e 47 } //1 DONT RUN IF YOU DONT KNOW WHAT YOU'RE DOING
		$a_01_8 = {50 72 65 73 73 20 59 45 53 20 6f 6e 6c 79 20 69 66 20 79 6f 75 20 6b 6e 6f 77 20 77 68 61 74 20 79 6f 75 27 72 65 20 64 6f 69 6e 67 2c 20 61 6e 64 20 69 73 20 69 6e 20 61 20 76 69 72 74 75 61 6c 20 4d 61 63 68 69 6e 65 } //1 Press YES only if you know what you're doing, and is in a virtual Machine
		$a_01_9 = {6d 6f 75 73 65 6d 6f 76 61 68 2e 65 78 65 } //1 mousemovah.exe
		$a_01_10 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 22 44 65 63 72 79 70 74 65 64 20 46 69 6c 65 2e 65 78 65 22 } //3 taskkill /f /im "Decrypted File.exe"
		$a_01_11 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 22 42 6c 75 65 20 57 61 76 65 2e 65 78 65 22 } //4 taskkill /f /im "Blue Wave.exe"
		$a_01_12 = {43 2b 2b 20 52 61 6e 73 6f 6d 2e 65 78 65 } //2 C++ Ransom.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*3+(#a_01_11  & 1)*4+(#a_01_12  & 1)*2) >=20
 
}