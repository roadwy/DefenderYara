
rule TrojanSpy_Win32_Banker_ANE{
	meta:
		description = "TrojanSpy:Win32/Banker.ANE,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0b 00 00 "
		
	strings :
		$a_01_0 = {2f 63 74 64 2f 6e 6f 74 69 2e 70 68 70 } //2 /ctd/noti.php
		$a_00_1 = {77 68 69 74 65 68 6f 75 73 65 2e 65 78 65 } //2 whitehouse.exe
		$a_00_2 = {40 75 6f 6c 2e 63 6f 6d 2e 62 72 } //2 @uol.com.br
		$a_00_3 = {62 72 61 64 65 73 63 6f 2e 72 65 63 61 64 61 73 74 72 61 6d 65 6e 74 6f 40 67 6d 61 69 6c 2e 63 6f 6d } //2 bradesco.recadastramento@gmail.com
		$a_00_4 = {72 69 74 61 6d 61 72 69 61 73 61 6e 74 6f 73 32 30 31 34 40 67 6d 61 69 6c 2e 63 6f 6d } //2 ritamariasantos2014@gmail.com
		$a_00_5 = {34 56 49 53 4f 3a 34 53 20 46 33 52 31 34 35 20 34 43 34 42 30 55 21 } //2 4VISO:4S F3R145 4C4B0U!
		$a_00_6 = {75 74 69 6c 64 72 6f 67 61 72 69 61 31 39 } //2 utildrogaria19
		$a_01_7 = {4e 2d 4f 2d 4d 2d 45 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 50 43 2e 3a } //2 N-O-M-E__________PC.:
		$a_01_8 = {4e 2a 4f 2a 4d 2a 45 2a 2d 2d 2d 2d 2d 2d 2d 2d 3e 50 43 2e 3a } //2 N*O*M*E*-------->PC.:
		$a_01_9 = {53 2d 45 2d 52 2d 49 2d 41 2d 4c 5f 5f 5f 5f 5f 5f 48 44 2e 3a } //2 S-E-R-I-A-L______HD.:
		$a_01_10 = {53 2a 45 2a 52 2a 49 2a 41 2a 4c 2a 2d 2d 2d 2d 3e 48 44 2e 3a } //2 S*E*R*I*A*L*---->HD.:
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2) >=8
 
}