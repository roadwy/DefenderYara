
rule TrojanSpy_Win32_Banker_ALB{
	meta:
		description = "TrojanSpy:Win32/Banker.ALB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 00 61 00 73 00 5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 63 00 65 00 66 00 2e 00 67 00 70 00 63 00 } //01 00  mas\GbPlugin\cef.gpc
		$a_01_1 = {2f 00 73 00 61 00 76 00 65 00 69 00 6e 00 66 00 65 00 63 00 74 00 63 00 78 00 2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 63 00 6c 00 69 00 3d 00 } //01 00  /saveinfectcx.php?idcli=
		$a_01_2 = {69 00 6e 00 73 00 5c 00 69 00 6e 00 66 00 67 00 61 00 74 00 } //01 00  ins\infgat
		$a_01_3 = {26 00 67 00 62 00 43 00 58 00 3d 00 } //00 00  &gbCX=
		$a_00_4 = {5d 04 00 } //00 f8 
	condition:
		any of ($a_*)
 
}