
rule TrojanSpy_Win32_Bancos_KB{
	meta:
		description = "TrojanSpy:Win32/Bancos.KB,SIGNATURE_TYPE_PEHSTR,47 00 47 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {53 54 46 4b 20 4d 75 74 65 78 58 78 } //10 STFK MutexXx
		$a_01_2 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //10 explorerbar
		$a_01_3 = {73 6d 74 70 2e 69 73 62 74 2e 63 6f 6d 2e 62 72 } //10 smtp.isbt.com.br
		$a_01_4 = {6d 78 32 2e 6d 61 69 6c 2e 79 61 68 6f 6f 2e 63 6f 6d } //10 mx2.mail.yahoo.com
		$a_01_5 = {49 54 41 20 41 67 65 6e 63 69 61 3a } //10 ITA Agencia:
		$a_01_6 = {49 54 41 20 6e 75 6d 65 72 6f 20 64 6f 20 70 6f 72 74 61 64 6f 72 3a } //10 ITA numero do portador:
		$a_01_7 = {63 30 6e 74 34 40 69 73 62 74 2e 63 6f 6d 2e 62 72 } //1 c0nt4@isbt.com.br
		$a_01_8 = {63 30 6e 74 34 40 79 61 68 6f 6f 2e 63 6f 6d 2e 62 72 } //1 c0nt4@yahoo.com.br
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=71
 
}