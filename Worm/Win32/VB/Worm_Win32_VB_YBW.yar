
rule Worm_Win32_VB_YBW{
	meta:
		description = "Worm:Win32/VB.YBW,SIGNATURE_TYPE_PEHSTR,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 4d 00 5c 00 4d 00 5c 00 42 00 75 00 73 00 68 00 20 00 76 00 31 00 30 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //2 \M\M\Bush v10\Project1.vbp
		$a_01_1 = {69 00 74 00 20 00 77 00 61 00 74 00 63 00 68 00 65 00 73 00 20 00 74 00 68 00 69 00 73 00 20 00 61 00 6e 00 69 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 62 00 75 00 73 00 68 00 20 00 3a 00 50 00 } //1 it watches this animation of bush :P
		$a_01_2 = {49 00 4d 00 57 00 69 00 6e 00 64 00 6f 00 77 00 43 00 6c 00 61 00 73 00 73 00 } //1 IMWindowClass
		$a_01_3 = {5c 00 4d 00 65 00 64 00 69 00 61 00 5c 00 49 00 6e 00 69 00 63 00 69 00 6f 00 20 00 64 00 65 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 58 00 50 00 2e 00 77 00 61 00 76 00 } //1 \Media\Inicio de Windows XP.wav
		$a_01_4 = {4d 00 53 00 4e 00 43 00 6c 00 65 00 61 00 6e 00 65 00 72 00 } //1 MSNCleaner
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}