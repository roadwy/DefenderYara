
rule Backdoor_Win32_EGroup_G{
	meta:
		description = "Backdoor:Win32/EGroup.G,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 45 47 45 78 63 65 70 74 69 6f 6e 3a 3a 43 45 47 45 78 63 65 70 74 69 6f 6e 28 29 20 65 6e 74 65 72 65 64 } //4 CEGException::CEGException() entered
		$a_01_1 = {65 67 68 6f 73 74 5f } //2 eghost_
		$a_01_2 = {64 6f 72 61 73 6d 6f 6e 69 74 6f 72 } //3 dorasmonitor
		$a_01_3 = {69 6e 73 74 61 6e 74 20 61 63 63 65 73 73 2e 65 78 65 } //2 instant access.exe
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=9
 
}
rule Backdoor_Win32_EGroup_G_2{
	meta:
		description = "Backdoor:Win32/EGroup.G,SIGNATURE_TYPE_PEHSTR,0c 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {65 67 68 74 6d 6c 64 69 61 6c 65 72 2e 64 6c 6c } //5 eghtmldialer.dll
		$a_01_1 = {68 74 74 70 3a 2f 2f 6e 65 74 77 6f 72 6b 2e 6e 6f 63 72 65 64 69 74 63 61 72 64 2e 63 6f 6d 2f 44 69 61 6c 48 54 4d 4c } //2 http://network.nocreditcard.com/DialHTML
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 65 67 72 6f 75 70 } //2 SOFTWARE\egroup
		$a_01_3 = {49 45 44 69 73 63 6f 53 68 6f 77 54 69 6d 65 } //1 IEDiscoShowTime
		$a_01_4 = {54 6f 70 4d 6f 73 74 49 45 44 69 73 63 6f } //1 TopMostIEDisco
		$a_01_5 = {54 68 65 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 68 61 73 20 62 65 65 6e 20 63 75 74 2c 20 64 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 63 6f 6e 6e 65 63 74 3f } //1 The connection has been cut, do you want to reconnect?
		$a_01_6 = {52 41 53 50 48 4f 4e 45 2e 45 58 45 } //1 RASPHONE.EXE
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}