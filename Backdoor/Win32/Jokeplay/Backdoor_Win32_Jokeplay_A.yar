
rule Backdoor_Win32_Jokeplay_A{
	meta:
		description = "Backdoor:Win32/Jokeplay.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 4a 00 6f 00 6b 00 65 00 2d 00 31 00 5c 00 70 00 72 00 6a 00 4a 00 6f 00 6b 00 65 00 2e 00 76 00 62 00 70 00 } //6 \Joke-1\prjJoke.vbp
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 65 00 64 00 69 00 61 00 2e 00 65 00 62 00 61 00 75 00 6d 00 73 00 77 00 6f 00 72 00 6c 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 69 00 63 00 68 00 61 00 2e 00 73 00 77 00 66 00 } //3 http://media.ebaumsworld.com/aicha.swf
		$a_01_2 = {43 00 3a 00 5c 00 67 00 75 00 2e 00 77 00 61 00 76 00 } //2 C:\gu.wav
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=9
 
}