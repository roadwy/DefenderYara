
rule Trojan_Win32_Agent_AGB{
	meta:
		description = "Trojan:Win32/Agent.AGB,SIGNATURE_TYPE_PEHSTR_EXT,5c 00 5a 00 12 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {73 74 72 69 70 5f 67 69 72 6c } //10 strip_girl
		$a_00_2 = {32 31 32 2e 31 37 39 2e 33 35 2e 33 31 } //10 212.179.35.31
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 53 47 50 6c 61 79 } //10 Software\SGPlay
		$a_00_4 = {3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //10 :\program files\internet explorer\iexplore.exe
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_01_6 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 ReadProcessMemory
		$a_00_7 = {57 53 41 53 74 61 72 74 75 70 } //10 WSAStartup
		$a_00_8 = {73 6f 63 6b 65 74 } //10 socket
		$a_00_9 = {69 6e 63 6f 72 72 65 63 74 20 68 6f 6e 65 79 21 20 4c 65 74 73 20 74 72 79 20 61 67 61 69 6e 3f } //1 incorrect honey! Lets try again?
		$a_00_10 = {4f 6b 2c 20 6c 65 74 73 20 73 74 61 72 74 20 62 61 62 79 21 20 4c 65 74 73 20 73 65 65 20 69 66 20 79 6f 75 20 63 61 6e 20 73 74 72 69 70 20 6d 65 20 3a 29 2e } //1 Ok, lets start baby! Lets see if you can strip me :).
		$a_00_11 = {74 61 6b 65 20 6f 66 66 20 31 20 6f 66 20 6d 79 20 78 78 78 20 3a 29 } //1 take off 1 of my xxx :)
		$a_00_12 = {57 61 69 74 20 66 6f 72 20 6e 65 77 20 77 6f 72 64 2c 20 70 6c 65 61 73 65 2c 20 73 77 65 65 74 69 65 20 3b 29 } //1 Wait for new word, please, sweetie ;)
		$a_00_13 = {59 6f 75 20 6e 65 65 64 20 74 6f 20 65 6e 74 65 72 20 77 6f 72 64 20 66 72 6f 6d 20 69 6d 61 67 65 20 69 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 73 65 65 20 6d 65 20 6e 61 6b 65 64 20 3b 29 } //1 You need to enter word from image if you want to see me naked ;)
		$a_00_14 = {49 27 6d 20 31 38 20 79 65 61 72 73 20 6f 6c 64 20 61 6e 64 20 79 6f 75 20 68 61 76 65 20 63 6f 6d 65 20 74 6f 20 74 68 65 } //1 I'm 18 years old and you have come to the
		$a_00_15 = {45 61 73 79 2c 20 65 6e 74 65 72 20 74 68 65 20 63 6f 64 65 20 74 68 61 74 20 79 6f 75 20 77 69 6c 6c 20 73 65 65 20 61 6e 64 20 49 27 6d 20 74 61 6b 69 6e 67 20 6f 66 66 } //1 Easy, enter the code that you will see and I'm taking off
		$a_00_16 = {31 20 6f 66 20 6d 79 20 74 68 69 6e 67 73 2e 20 3a 29 20 57 61 6e 74 20 74 6f 20 73 74 61 72 74 20 73 74 72 69 70 20 6d 65 3f 20 54 68 65 6e 20 77 68 61 74 20 61 72 65 20 79 6f 75 } //1 1 of my things. :) Want to start strip me? Then what are you
		$a_00_17 = {77 61 69 74 69 6e 67 20 66 6f 72 3f 20 43 6c 69 63 6b 20 74 68 65 20 73 74 61 72 74 20 70 6c 61 79 2e } //1 waiting for? Click the start play.
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1) >=90
 
}