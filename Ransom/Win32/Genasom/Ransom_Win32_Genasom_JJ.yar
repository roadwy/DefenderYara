
rule Ransom_Win32_Genasom_JJ{
	meta:
		description = "Ransom:Win32/Genasom.JJ,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {71 77 65 72 74 79 31 37 5f 31 32 33 34 35 } //1 qwerty17_12345
		$a_01_1 = {68 74 74 70 3a 2f 2f 00 52 4c 00 } //1
		$a_01_2 = {64 6c 6c 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 5c 5c 2e 5c 50 48 59 53 49 43 41 4c 44 52 49 56 45 30 } //1 汤l敓桓瑵潤湷牐癩汩来e屜尮䡐卙䍉䱁剄噉ぅ
		$a_03_3 = {8a 08 40 84 c9 75 ?? 2b c6 8b c8 8d 74 14 ?? 33 c0 f3 a6 74 ?? 1b c0 83 d8 ff 85 c0 0f 84 ?? ?? 00 00 42 81 fa 00 02 00 00 72 ?? 6a 00 6a 00 68 00 02 00 00 53 ff 15 ?? ?? ?? ?? 83 f8 ff } //2
		$a_01_4 = {ba 80 00 b9 03 00 b8 03 02 bb 00 10 cd 13 73 05 b8 47 0e cd 10 b8 00 11 bd 00 10 b9 40 00 ba c0 00 b7 10 b3 00 cd 10 ba 80 00 b9 05 00 b8 04 02 bb 00 30 cd 13 66 60 b8 01 13 bb 0c 00 b9 30 07 31 d2 bd 00 30 cd 10 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2+(#a_01_4  & 1)*3) >=8
 
}