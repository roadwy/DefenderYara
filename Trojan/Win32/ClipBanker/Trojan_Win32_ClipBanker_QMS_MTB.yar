
rule Trojan_Win32_ClipBanker_QMS_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.QMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 69 6c 65 44 65 6c 65 74 65 2c 20 25 41 5f 53 63 72 69 70 74 44 69 72 25 5c 53 4e 2e 74 78 74 } //01 00  FileDelete, %A_ScriptDir%\SN.txt
		$a_81_1 = {63 6c 69 63 6b 28 37 38 36 2c 20 32 38 38 2c 30 2e 34 2c 32 35 30 29 } //01 00  click(786, 288,0.4,250)
		$a_81_2 = {63 6c 69 63 6b 28 37 37 39 2c 34 30 30 2c 30 2e 34 2c 32 35 30 29 } //01 00  click(779,400,0.4,250)
		$a_81_3 = {23 33 32 37 36 38 20 61 68 6b 5f 65 78 65 20 41 75 74 6f 48 6f 74 6b 65 79 2e 65 78 65 } //01 00  #32768 ahk_exe AutoHotkey.exe
		$a_81_4 = {79 63 68 71 77 65 72 31 32 33 } //01 00  ychqwer123
		$a_81_5 = {47 65 74 48 61 73 68 28 73 74 72 2c 76 29 } //00 00  GetHash(str,v)
	condition:
		any of ($a_*)
 
}