
rule TrojanSpy_Win32_Banker_VJ{
	meta:
		description = "TrojanSpy:Win32/Banker.VJ,SIGNATURE_TYPE_PEHSTR_EXT,5c 00 5c 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //50 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {50 6f 72 20 46 61 76 6f 72 2c 20 72 65 64 69 67 69 74 65 20 61 20 70 6f 73 69 } //10 Por Favor, redigite a posi
		$a_00_2 = {49 4e 54 45 52 4e 45 54 20 42 41 4e 4b 49 4e 47 20 43 41 49 58 41 } //10 INTERNET BANKING CAIXA
		$a_00_3 = {51 37 48 71 53 37 43 77 42 6f 7a 74 54 74 } //10 Q7HqS7CwBoztTt
		$a_00_4 = {52 43 50 54 20 54 4f 3a 3c } //5 RCPT TO:<
		$a_00_5 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c } //5 MAIL FROM:<
		$a_01_6 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_00_7 = {57 69 6e 45 78 65 63 } //1 WinExec
	condition:
		((#a_00_0  & 1)*50+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*5+(#a_00_5  & 1)*5+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=92
 
}