
rule Worm_Win32_Voterai_H{
	meta:
		description = "Worm:Win32/Voterai.H,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 61 69 6c 61 4f 2e 65 78 65 } //1 RailaO.exe
		$a_01_1 = {5c 52 61 69 6c 61 20 4f 64 69 6e 67 61 2e 65 78 65 } //1 \Raila Odinga.exe
		$a_01_2 = {52 61 69 6c 61 20 4f 64 69 6e 67 61 2e 67 69 66 } //1 Raila Odinga.gif
		$a_01_3 = {25 5c 64 72 69 76 65 72 73 5c } //1 %\drivers\
		$a_01_4 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 \autorun.inf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}