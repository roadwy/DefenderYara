
rule Trojan_Win32_Agent_NAH{
	meta:
		description = "Trojan:Win32/Agent.NAH,SIGNATURE_TYPE_PEHSTR_EXT,21 00 20 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6e 75 73 72 6d 67 72 2e 65 78 65 } //0a 00  nusrmgr.exe
		$a_00_1 = {68 74 74 70 3a 2f 2f 6c 69 76 65 75 70 64 61 74 65 73 6e 65 74 2e 63 6f 6d 2f } //0a 00  http://liveupdatesnet.com/
		$a_01_2 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_00_3 = {48 54 54 50 2f 31 2e 31 } //01 00  HTTP/1.1
		$a_00_4 = {2f 6d 2e 70 68 70 3f 61 69 64 3d } //01 00  /m.php?aid=
		$a_00_5 = {76 6d 77 61 72 65 73 65 72 76 69 63 65 2e 65 78 65 } //01 00  vmwareservice.exe
		$a_00_6 = {6c 6f 61 64 65 72 2e 65 78 65 } //00 00  loader.exe
	condition:
		any of ($a_*)
 
}