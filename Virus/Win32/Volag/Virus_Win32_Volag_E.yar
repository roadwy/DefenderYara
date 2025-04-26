
rule Virus_Win32_Volag_E{
	meta:
		description = "Virus:Win32/Volag.E,SIGNATURE_TYPE_PEHSTR,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 33 32 2e 56 6f 6c 74 61 67 65 20 56 69 72 75 73 20 57 72 69 74 74 65 6e 20 42 79 20 44 52 2d 45 46 20 28 63 29 20 32 30 30 34 } //1 Win32.Voltage Virus Written By DR-EF (c) 2004
		$a_01_1 = {52 65 61 64 4d 65 2e 65 78 65 } //1 ReadMe.exe
		$a_01_2 = {44 49 52 53 5c 42 4f 58 5c 57 33 32 5f 56 4f 4c 54 41 47 45 2e 45 58 45 } //1 DIRS\BOX\W32_VOLTAGE.EXE
		$a_01_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 5c 77 76 6c 74 67 2e 65 78 65 } //1 C:\WINDOWS\SYSTEM\wvltg.exe
		$a_01_4 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 53 65 63 75 72 69 74 79 55 70 64 61 74 65 40 4d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 3e } //1 MAIL FROM:<SecurityUpdate@Microsoft.com>
		$a_01_5 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 46 72 65 65 50 69 63 74 75 72 65 73 40 57 6f 72 6c 64 53 65 78 2e 63 6f 6d 3e } //1 MAIL FROM:<FreePictures@WorldSex.com>
		$a_01_6 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 56 69 72 75 73 41 6c 65 72 74 40 53 79 6d 61 6e 74 65 63 2e 63 6f 6d 3e } //1 MAIL FROM:<VirusAlert@Symantec.com>
		$a_01_7 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 53 75 70 70 6f 72 74 40 4b 61 7a 61 61 2e 63 6f 6d 3e } //1 MAIL FROM:<Support@Kazaa.com>
		$a_01_8 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 47 72 65 65 74 73 40 47 72 65 65 74 69 6e 67 2d 43 61 72 64 73 2e 63 6f 6d 3e } //1 MAIL FROM:<Greets@Greeting-Cards.com>
		$a_01_9 = {66 69 6c 65 6e 61 6d 65 3d 20 22 31 35 30 5f 58 58 58 5f 50 69 63 74 75 72 65 73 2e 65 78 65 22 } //1 filename= "150_XXX_Pictures.exe"
		$a_01_10 = {44 65 61 72 20 53 79 6d 61 6e 74 65 63 2f 46 2d 53 65 63 75 72 65 2f 4d 63 61 66 65 65 2f 54 72 65 6e 64 20 4d 69 63 72 6f 20 55 73 65 72 } //1 Dear Symantec/F-Secure/Mcafee/Trend Micro User
		$a_01_11 = {66 69 6c 65 6e 61 6d 65 3d 20 22 4b 61 7a 61 61 20 4d 65 64 69 61 20 44 65 73 6b 74 6f 70 2e 65 78 65 22 } //1 filename= "Kazaa Media Desktop.exe"
		$a_01_12 = {47 72 65 65 74 69 6e 67 2d 43 61 72 64 73 2e 63 6f 6d 20 68 61 76 65 20 73 65 6e 74 20 79 6f 75 20 61 20 47 72 65 65 74 69 6e 67 20 43 61 72 64 } //1 Greeting-Cards.com have sent you a Greeting Card
		$a_01_13 = {66 69 6c 65 6e 61 6d 65 3d 20 22 59 6f 75 72 20 47 72 65 65 74 69 6e 67 20 43 61 72 64 2e 65 78 65 22 } //1 filename= "Your Greeting Card.exe"
		$a_01_14 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 41 42 5c 57 41 42 34 5c 57 61 62 20 46 69 6c 65 20 4e 61 6d 65 } //1 Software\Microsoft\WAB\WAB4\Wab File Name
		$a_01_15 = {66 2d 74 62 61 77 61 6e 74 69 7a 6f 6e 65 73 63 61 6e 70 72 6f 74 6d 6f 6e 69 72 77 65 62 6d 69 72 63 63 6b 64 6f 74 72 6f 6a 73 61 66 65 6a 65 64 69 74 72 61 79 61 6e 64 61 69 6e 6f 63 73 70 69 64 70 6c 6f 72 6e 64 6c 6c 74 72 65 6e 61 6d 6f 6e 6e 73 70 6c 6e 73 63 68 6e 6f 64 33 61 6c 65 72 73 6d 73 73 68 } //1 f-tbawantizonescanprotmonirwebmircckdotrojsafejeditrayandainocspidplorndlltrenamonnsplnschnod3alersmssh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}