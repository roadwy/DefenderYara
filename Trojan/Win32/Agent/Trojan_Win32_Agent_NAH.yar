
rule Trojan_Win32_Agent_NAH{
	meta:
		description = "Trojan:Win32/Agent.NAH,SIGNATURE_TYPE_PEHSTR_EXT,21 00 20 00 07 00 00 "
		
	strings :
		$a_00_0 = {6e 75 73 72 6d 67 72 2e 65 78 65 } //10 nusrmgr.exe
		$a_00_1 = {68 74 74 70 3a 2f 2f 6c 69 76 65 75 70 64 61 74 65 73 6e 65 74 2e 63 6f 6d 2f } //10 http://liveupdatesnet.com/
		$a_01_2 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //10 MSVBVM60.DLL
		$a_00_3 = {48 54 54 50 2f 31 2e 31 } //1 HTTP/1.1
		$a_00_4 = {2f 6d 2e 70 68 70 3f 61 69 64 3d } //1 /m.php?aid=
		$a_00_5 = {76 6d 77 61 72 65 73 65 72 76 69 63 65 2e 65 78 65 } //1 vmwareservice.exe
		$a_00_6 = {6c 6f 61 64 65 72 2e 65 78 65 } //1 loader.exe
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=32
 
}