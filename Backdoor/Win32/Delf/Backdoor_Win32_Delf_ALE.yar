
rule Backdoor_Win32_Delf_ALE{
	meta:
		description = "Backdoor:Win32/Delf.ALE,SIGNATURE_TYPE_PEHSTR,33 00 33 00 08 00 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //10 explorerbar
		$a_01_1 = {5c 77 73 61 73 73 33 32 2e 65 78 65 } //10 \wsass32.exe
		$a_01_2 = {49 4e 46 45 43 54 41 4e 44 4f 4f 4f } //10 INFECTANDOOO
		$a_01_3 = {49 6e 66 65 63 74 61 64 6f 20 4f 6e 4c 69 6e 65 } //10 Infectado OnLine
		$a_01_4 = {4f 42 41 41 41 20 54 45 4d 20 46 45 53 54 41 20 48 4f 4a 45 45 45 45 } //10 OBAAA TEM FESTA HOJEEEE
		$a_01_5 = {6d 73 74 78 74 73 40 67 6d 61 69 6c 2e 63 6f 6d } //1 mstxts@gmail.com
		$a_01_6 = {63 61 72 64 65 72 78 40 67 6d 61 69 6c 2e 63 6f 6d } //1 carderx@gmail.com
		$a_01_7 = {72 61 66 61 35 36 33 33 34 35 36 35 34 34 40 67 6d 61 69 6c 2e 63 6f 6d } //1 rafa5633456544@gmail.com
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=51
 
}