
rule TrojanSpy_Win32_Banker_AFB{
	meta:
		description = "TrojanSpy:Win32/Banker.AFB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 08 00 00 "
		
	strings :
		$a_02_0 = {6c 62 6c 42 72 6f 77 73 65 72 41 6e 65 78 61 64 6f [0-36] 62 6c 6f 71 75 65 } //10
		$a_00_1 = {62 6c 6f 63 6b 69 6e 70 75 74 } //2 blockinput
		$a_00_2 = {67 65 74 65 78 65 } //2 getexe
		$a_00_3 = {6d 6f 75 73 65 68 6f 6f 6b } //2 mousehook
		$a_00_4 = {66 69 72 65 66 6f 78 2e 65 78 65 } //1 firefox.exe
		$a_00_5 = {68 6f 74 6d 61 69 6c } //1 hotmail
		$a_00_6 = {62 61 6e 63 6f } //1 banco
		$a_00_7 = {2e 63 6f 6d 2e 62 72 } //1 .com.br
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=18
 
}