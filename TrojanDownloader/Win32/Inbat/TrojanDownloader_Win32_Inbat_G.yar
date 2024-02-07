
rule TrojanDownloader_Win32_Inbat_G{
	meta:
		description = "TrojanDownloader:Win32/Inbat.G,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 4d 59 46 49 4c 45 53 25 5c 69 6e 2e 65 78 65 } //01 00  %MYFILES%\in.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 73 74 61 74 2e 30 32 39 33 33 2e 63 6f 6d } //01 00  http://stat.02933.com
		$a_01_2 = {6d 73 68 74 61 20 76 62 73 63 72 69 70 74 3a 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 72 75 6e 28 22 22 22 69 65 78 70 6c 6f 72 65 22 22 68 74 74 70 3a 2f 2f } //01 00  mshta vbscript:createobject("wscript.shell").run("""iexplore""http://
		$a_01_3 = {5c 33 36 30 73 61 66 65 2e 65 78 65 } //01 00  \360safe.exe
		$a_01_4 = {5c 4b 53 57 65 62 53 68 69 65 6c 64 2e 65 78 65 } //01 00  \KSWebShield.exe
		$a_01_5 = {5c 6b 77 73 2e 69 6e 69 } //00 00  \kws.ini
	condition:
		any of ($a_*)
 
}