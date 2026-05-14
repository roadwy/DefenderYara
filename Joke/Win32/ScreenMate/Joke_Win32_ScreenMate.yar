
rule Joke_Win32_ScreenMate{
	meta:
		description = "Joke:Win32/ScreenMate,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 65 73 73 61 67 65 20 4d 61 74 65 } //1 Message Mate
		$a_01_1 = {53 63 72 65 65 6e 20 4d 61 74 65 } //1 Screen Mate
		$a_01_2 = {44 65 76 5c 43 6f 64 65 5c 50 72 6f 64 75 63 74 69 6f 6e 73 5c 4d 61 6e 6e 79 4e 65 77 4d 65 73 73 61 67 65 4d 61 74 65 73 5c 68 6f 74 73 74 75 66 66 5c 73 63 65 6e 65 2e 63 70 70 } //1 Dev\Code\Productions\MannyNewMessageMates\hotstuff\scene.cpp
		$a_01_3 = {57 65 3e 68 69 } //1 We>hi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}