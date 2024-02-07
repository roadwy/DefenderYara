
rule Trojan_Win32_Eyesow_A{
	meta:
		description = "Trojan:Win32/Eyesow.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 41 69 53 6f 53 6f } //01 00  Software\Microsoft\Windows\CurrentVersion\explorer\AiSoSo
		$a_01_1 = {2f 58 51 44 42 48 4f 43 6f 6e 66 69 67 2e 61 73 70 78 3f 76 65 72 3d } //01 00  /XQDBHOConfig.aspx?ver=
		$a_01_2 = {54 49 64 41 6e 74 69 46 72 65 65 7a 65 } //00 00  TIdAntiFreeze
	condition:
		any of ($a_*)
 
}