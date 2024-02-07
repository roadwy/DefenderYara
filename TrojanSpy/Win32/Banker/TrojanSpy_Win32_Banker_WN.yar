
rule TrojanSpy_Win32_Banker_WN{
	meta:
		description = "TrojanSpy:Win32/Banker.WN,SIGNATURE_TYPE_PEHSTR,23 00 21 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {75 69 64 3d 25 73 26 77 61 73 3d 25 64 26 6c 65 66 74 3d 25 64 26 73 65 6e 74 3d 25 64 26 72 65 61 6c 73 65 6e 74 3d 25 64 26 64 72 6f 70 6e 61 6d 65 3d 25 73 26 62 61 6e 6b 6e 61 6d 65 3d 25 73 26 75 72 6c 3d 25 73 26 64 61 74 65 74 69 6d 65 3d 25 73 } //0a 00  uid=%s&was=%d&left=%d&sent=%d&realsent=%d&dropname=%s&bankname=%s&url=%s&datetime=%s
		$a_01_1 = {2f 67 65 74 7a 61 6c 69 76 69 2e 70 68 70 } //0a 00  /getzalivi.php
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 25 73 3f 73 65 61 72 63 68 3d 25 73 } //01 00  http://%s%s?search=%s
		$a_01_3 = {63 73 72 73 73 2e 65 78 65 } //01 00  csrss.exe
		$a_01_4 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_01_5 = {74 61 73 6b 6d 67 72 2e 65 78 65 } //01 00  taskmgr.exe
		$a_01_6 = {70 73 74 6f 72 65 63 2e 64 6c 6c } //01 00  pstorec.dll
		$a_01_7 = {50 53 74 6f 72 65 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  PStoreCreateInstance
	condition:
		any of ($a_*)
 
}