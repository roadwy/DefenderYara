
rule TrojanDownloader_WinNT_Banload_Q{
	meta:
		description = "TrojanDownloader:WinNT/Banload.Q,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3f 64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 3d 74 72 75 65 } //01 00  ?directDownload=true
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 73 75 67 61 72 73 79 6e 63 2e 63 6f 6d 2f 70 66 } //01 00  https://www.sugarsync.com/pf
		$a_01_2 = {21 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 52 75 6e 64 6c 6c 33 32 2e 65 78 65 } //01 00  !C:\Windows\System32\Rundll32.exe
		$a_01_3 = {42 61 6e 67 2e 6a 61 76 61 } //00 00  Bang.java
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_WinNT_Banload_Q_2{
	meta:
		description = "TrojanDownloader:WinNT/Banload.Q,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2f 44 33 32 33 33 38 32 37 5f 37 37 35 5f 32 35 33 38 32 90 02 08 3f 64 69 72 65 63 74 44 6f 77 6e 6c 6f 61 64 3d 74 72 75 65 90 00 } //01 00 
		$a_01_1 = {46 69 72 6d 61 5f 69 6e 69 63 69 61 6e 64 6f 2f 54 72 61 6e 73 70 6f 72 74 65 } //01 00  Firma_iniciando/Transporte
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 73 75 67 61 72 73 79 6e 63 2e 63 6f 6d 2f 70 66 } //00 00  https://www.sugarsync.com/pf
	condition:
		any of ($a_*)
 
}