
rule TrojanSpy_Win32_Banker_NH{
	meta:
		description = "TrojanSpy:Win32/Banker.NH,SIGNATURE_TYPE_PEHSTR,55 00 53 00 0d 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {4d 61 63 20 41 64 64 72 65 73 73 2e 2e 2e 2e 3a } //10 Mac Address....:
		$a_01_2 = {43 61 69 78 61 } //10 Caixa
		$a_01_3 = {43 75 72 73 6f 72 73 5c 61 65 72 6f 5f 6c 69 6e 6b 2e 63 75 72 } //10 Cursors\aero_link.cur
		$a_01_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 6c 69 62 65 61 79 33 32 2e 64 6c 6c } //10 C:\WINDOWS\system32\libeay32.dll
		$a_01_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 73 73 6c 65 61 79 33 32 2e 64 6c 6c } //10 C:\WINDOWS\system32\ssleay32.dll
		$a_01_6 = {49 64 65 6e 74 69 66 69 63 61 63 69 6f 6e 2e 2e 3a } //10 Identificacion..:
		$a_01_7 = {4d 79 73 61 6d 70 6c 65 41 70 70 4d 75 74 65 78 } //10 MysampleAppMutex
		$a_01_8 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c 72 66 6b 73 61 64 76 6e 71 69 6e 64 79 77 33 6e 65 72 61 73 64 66 } //1 =_NextPart_2relrfksadvnqindyw3nerasdf
		$a_01_9 = {48 6f 72 61 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a } //1 Hora...........:
		$a_01_10 = {50 49 4e 31 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a } //1 PIN1............:
		$a_01_11 = {53 65 72 69 65 20 48 44 2e 2e 2e 2e 3a } //1 Serie HD....:
		$a_01_12 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 4b 42 31 31 30 38 30 39 2e 74 78 74 } //1 C:\WINDOWS\KB110809.txt
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=83
 
}