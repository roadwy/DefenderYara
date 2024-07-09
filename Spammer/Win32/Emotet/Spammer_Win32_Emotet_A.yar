
rule Spammer_Win32_Emotet_A{
	meta:
		description = "Spammer:Win32/Emotet.A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 09 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6c 69 6b 65 73 6f 6d 65 73 73 66 6f 72 74 65 6c 72 2e 65 75 2f 6d 53 73 4e 58 33 4a 44 53 4a 44 2f 69 6e 4e 53 6a 33 39 38 4c 53 6a 2f } //1 http://likesomessfortelr.eu/mSsNX3JDSJD/inNSj398LSj/
		$a_01_1 = {68 74 74 70 3a 2f 2f 61 6a 65 79 66 74 72 6a 71 65 61 73 68 67 64 61 2e 6d 6f 62 69 2f 6d 53 73 51 44 49 4d 49 51 2f 69 6e 49 44 77 2f } //1 http://ajeyftrjqeashgda.mobi/mSsQDIMIQ/inIDw/
		$a_01_2 = {68 74 74 70 3a 2f 2f 71 77 75 79 65 67 61 73 64 33 65 64 61 72 71 36 79 75 2e 6f 72 67 2f 6d 53 73 51 44 49 4d 49 51 2f 69 6e 64 37 36 39 34 47 44 73 2f } //1 http://qwuyegasd3edarq6yu.org/mSsQDIMIQ/ind7694GDs/
		$a_01_3 = {63 72 79 73 70 65 6c 6c 69 6e 67 73 6c 61 76 65 73 65 64 75 63 61 74 69 6f 6e 2e 65 75 2f 6d 33 39 6b 4e 53 4a 4a 2f 69 37 33 79 44 4a 6e 6a 64 65 2f } //1 cryspellingslaveseducation.eu/m39kNSJJ/i73yDJnjde/
		$a_01_4 = {68 74 74 70 3a 2f 2f 62 61 72 64 75 62 61 72 2e 63 6f 6d 2f 6d 4d 53 38 33 4a 49 64 68 71 2f 69 65 79 67 42 53 48 33 38 68 73 4a 61 2f } //1 http://bardubar.com/mMS83JIdhq/ieygBSH38hsJa/
		$a_03_5 = {8b 46 08 8b 56 04 8b 7c 24 10 8d 4c 24 08 51 8b 0e 2b d0 52 8b 97 44 02 00 00 03 c8 51 52 ff 15 ?? ?? ?? ?? 85 c0 74 29 } //1
		$a_01_6 = {64 65 6c 20 2f 51 20 2f 46 20 22 25 53 22 } //10 del /Q /F "%S"
		$a_01_7 = {25 00 73 00 5c 00 5f 00 74 00 6d 00 70 00 78 00 71 00 72 00 2e 00 62 00 61 00 74 00 } //10 %s\_tmpxqr.bat
		$a_01_8 = {6d 79 20 68 75 67 65 20 65 6e 74 72 6f 70 79 20 66 6f 72 20 72 6e 67 2e 2e 20 62 6c 61 68 } //10 my huge entropy for rng.. blah
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10) >=31
 
}