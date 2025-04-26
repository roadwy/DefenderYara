
rule Trojan_Win64_DriverLoader_DB_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_81_0 = {4d 79 57 46 48 61 63 6b 5c 43 72 79 4b 69 6c 6c 65 72 5c 4e 45 57 20 42 59 50 41 53 53 5c 77 31 6e 6e 65 72 } //10 MyWFHack\CryKiller\NEW BYPASS\w1nner
		$a_81_1 = {6d 77 31 39 20 63 68 61 69 72 5c 6d 64 20 64 64 6c 73 5c 42 6c 61 63 6b 5f 4c 6f 61 64 65 72 } //10 mw19 chair\md ddls\Black_Loader
		$a_81_2 = {6d 77 31 39 20 73 72 63 73 5c 69 6e 6a 5c 69 6d 67 75 69 20 69 6e 6a 5c 70 6c 6f 31 78 6d 6f 64 7a 5c 6f 75 74 70 75 74 5c 6d 77 31 39 6c 6f 61 64 65 72 } //10 mw19 srcs\inj\imgui inj\plo1xmodz\output\mw19loader
		$a_81_3 = {53 75 6e 73 65 74 49 6e 6a 65 63 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 53 75 6e 73 65 74 49 6e 6a 65 63 74 } //10 SunsetInject\x64\Release\SunsetInject
		$a_81_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4d 6f 64 65 72 6e 57 61 72 66 61 72 65 2e 65 78 65 } //1 taskkill /f /im ModernWarfare.exe
		$a_81_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 63 6f 64 2e 65 78 65 } //1 taskkill /f /im cod.exe
		$a_81_6 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 73 74 65 61 6d 2e 65 78 65 } //1 taskkill /f /im steam.exe
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=13
 
}