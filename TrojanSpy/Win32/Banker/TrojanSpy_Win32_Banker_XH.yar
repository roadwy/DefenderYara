
rule TrojanSpy_Win32_Banker_XH{
	meta:
		description = "TrojanSpy:Win32/Banker.XH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 50 8b 45 fc 50 6a 07 6a 00 68 90 01 04 8b 43 04 50 e8 90 00 } //01 00 
		$a_01_1 = {5c 3f 3f 5c 63 3a 5c 57 49 4e 44 4f 57 53 5c 72 61 70 70 6f 72 74 43 6c 65 61 6e 31 2e 74 78 74 } //01 00  \??\c:\WINDOWS\rapportClean1.txt
		$a_01_2 = {21 5c 3f 3f 5c 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 54 72 75 73 74 65 65 72 5c 52 61 70 70 6f 72 74 5c 6a 73 5c 63 6f 6e 66 69 67 2e 6a 73 } //01 00  !\??\C:\Program Files\Trusteer\Rapport\js\config.js
		$a_01_3 = {50 65 6e 64 69 6e 67 46 69 6c 65 52 65 6e 61 6d 65 4f 70 65 72 61 74 69 6f 6e 73 00 } //00 00  敐摮湩䙧汩剥湥浡佥数慲楴湯s
	condition:
		any of ($a_*)
 
}