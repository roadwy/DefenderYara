
rule TrojanSpy_Win32_Maran_gen_C{
	meta:
		description = "TrojanSpy:Win32/Maran.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 19 00 09 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //5 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {64 65 6c 6d 65 6d 6c 2e 62 61 74 } //5 delmeml.bat
		$a_01_2 = {4d 00 53 00 41 00 46 00 44 00 20 00 54 00 63 00 70 00 69 00 70 00 20 00 5b 00 54 00 43 00 50 00 2f 00 49 00 50 00 5d 00 } //5 MSAFD Tcpip [TCP/IP]
		$a_01_3 = {44 00 4c 00 4c 00 43 00 46 00 47 00 } //5 DLLCFG
		$a_01_4 = {68 74 6f 6e 73 } //1 htons
		$a_00_5 = {73 6f 63 6b 65 74 } //1 socket
		$a_01_6 = {57 53 43 47 65 74 50 72 6f 76 69 64 65 72 50 61 74 68 } //1 WSCGetProviderPath
		$a_01_7 = {57 53 43 45 6e 75 6d 50 72 6f 74 6f 63 6f 6c 73 } //1 WSCEnumProtocols
		$a_01_8 = {69 70 66 69 6c 74 65 72 2e 64 6c 6c } //1 ipfilter.dll
	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=25
 
}