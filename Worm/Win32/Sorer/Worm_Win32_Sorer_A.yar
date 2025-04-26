
rule Worm_Win32_Sorer_A{
	meta:
		description = "Worm:Win32/Sorer.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 66 57 69 6e 45 78 69 73 74 2c 20 57 69 6e 61 6d 70 0d 0a 7b 0d 0a 0d 0a 43 6f 6e 74 72 6f 6c 46 6f 63 75 73 2c 20 2c 20 57 69 6e 61 6d 70 0d 0a 53 65 6e 64 20 21 7b 46 34 7d 0d 0a 4d 73 67 42 6f 78 20 34 31 31 32 2c 4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 20 57 61 72 6e 69 6e 67 2c 22 57 65 20 61 72 65 20 73 6f 72 72 79 } //1
		$a_01_1 = {46 69 6c 65 43 6f 70 79 2c 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 2c 25 } //1 FileCopy,C:\WINDOWS\system\Autorun.inf,%
		$a_01_2 = {46 69 6c 65 43 6f 70 79 2c 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 5c 73 76 63 2e 65 78 65 2c 25 } //1 FileCopy,C:\WINDOWS\system\svc.exe,%
		$a_01_3 = {49 66 57 69 6e 45 78 69 73 74 2c 20 56 4c 43 0d 0a 7b 0d 0a 77 69 6e 63 6c 6f 73 65 } //1
		$a_01_4 = {4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 2c 22 59 6f 75 20 61 72 65 20 75 73 69 6e 67 20 61 20 70 69 72 61 74 65 64 28 69 6c 6c 65 67 61 6c 29 20 76 65 72 73 69 6f 6e 20 6f 66 20 4d 69 63 72 6f 73 6f 66 74 2e 60 6e 59 6f 75 20 6d 61 79 20 65 6e 63 6f 75 6e 74 65 72 20 73 65 76 65 72 65 20 50 65 6e 61 6c 74 69 65 73 20 66 6f 72 20 74 68 69 73 20 6b 69 6e 64 20 6f 66 20 61 63 74 69 6f 6e 2e 60 6e 50 6c 65 61 73 65 20 52 65 67 69 73 74 65 72 20 79 6f 75 72 20 63 6f 70 79 20 61 74 20 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //1 Microsoft Windows,"You are using a pirated(illegal) version of Microsoft.`nYou may encounter severe Penalties for this kind of action.`nPlease Register your copy at www.microsoft.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}