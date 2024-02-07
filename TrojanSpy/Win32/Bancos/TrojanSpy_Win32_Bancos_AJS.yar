
rule TrojanSpy_Win32_Bancos_AJS{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJS,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {7b 44 45 4c 45 54 45 7d } //01 00  {DELETE}
		$a_01_1 = {54 00 4c 00 4f 00 47 00 49 00 4e 00 44 00 49 00 41 00 4c 00 4f 00 47 00 } //02 00  TLOGINDIALOG
		$a_01_2 = {45 64 69 74 4e 75 6d 30 39 39 4b 65 79 50 72 65 73 73 } //02 00  EditNum099KeyPress
		$a_01_3 = {49 6d 61 67 65 32 34 43 6c 69 63 6b } //02 00  Image24Click
		$a_01_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 6e 65 74 } //03 00  SELECT * FROM net
		$a_01_5 = {45 64 69 74 43 6f 64 30 32 4b 65 79 50 72 65 73 73 } //03 00  EditCod02KeyPress
		$a_01_6 = {45 64 69 74 54 61 62 34 5f 49 74 61 4b 65 79 50 72 65 73 73 } //03 00  EditTab4_ItaKeyPress
		$a_01_7 = {8b 55 f0 0f b7 44 50 fe 33 45 e0 89 45 dc 8b 45 dc 3b 45 ec 7f 10 8b 45 dc 05 ff 00 00 00 } //00 00 
		$a_00_8 = {5d 04 00 00 9e 07 03 } //80 5c 
	condition:
		any of ($a_*)
 
}