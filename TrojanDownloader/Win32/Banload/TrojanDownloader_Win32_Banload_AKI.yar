
rule TrojanDownloader_Win32_Banload_AKI{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKI,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 62 79 6d 69 78 2e 72 75 2f } //01 00  //bymix.ru/
		$a_01_1 = {2f 76 69 72 2f 6c 69 6e 6b 2e 70 68 70 } //01 00  /vir/link.php
		$a_01_2 = {2f 76 69 72 2f 62 61 7a 61 2e 70 68 70 } //01 00  /vir/baza.php
		$a_01_3 = {2f 76 69 72 2f 74 69 6d 65 2e 70 68 70 } //01 00  /vir/time.php
		$a_01_4 = {2f 76 69 72 2f 75 70 2e 65 78 65 } //01 00  /vir/up.exe
		$a_01_5 = {2f 76 69 72 2f 76 65 72 2e 70 68 70 } //01 00  /vir/ver.php
		$a_01_6 = {44 69 73 61 62 6c 65 53 63 72 69 70 74 44 65 62 75 67 67 65 72 49 45 } //01 00  DisableScriptDebuggerIE
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //00 00  Software\Microsoft\Internet Explorer\Main
	condition:
		any of ($a_*)
 
}