
rule Ransom_Win32_LockScreen_BR{
	meta:
		description = "Ransom:Win32/LockScreen.BR,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {b0 6f b1 57 83 c4 0c c6 45 a0 53 c6 45 a1 65 c6 45 a2 74 88 4d a3 c6 45 a4 69 c6 45 a5 6e } //01 00 
		$a_01_1 = {ff d3 50 8b 5d 84 ff d3 89 85 68 ff ff ff 33 c9 89 4d 94 b8 } //01 00 
		$a_01_2 = {3b c8 72 0a 8b c1 59 94 8b 00 89 04 24 c3 2d 00 10 00 00 85 00 eb e9 } //01 00 
		$a_01_3 = {74 18 8d 9d 44 f9 ff ff 53 8b 9d 20 f9 ff ff ff d3 50 8b 9d 24 f9 ff ff ff d3 68 06 02 00 00 } //0a 00 
		$a_00_4 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 46 00 20 00 2f 00 49 00 4d 00 20 00 74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  taskkill /F /IM taskmgr.exe
	condition:
		any of ($a_*)
 
}