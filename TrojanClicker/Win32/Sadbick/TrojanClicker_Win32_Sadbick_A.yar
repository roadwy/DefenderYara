
rule TrojanClicker_Win32_Sadbick_A{
	meta:
		description = "TrojanClicker:Win32/Sadbick.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 50 00 75 00 73 00 68 00 4d 00 69 00 73 00 73 00 69 00 6f 00 6e 00 32 00 43 00 6c 00 69 00 65 00 6e 00 74 00 30 00 33 00 2e 00 61 00 73 00 70 00 } //01 00  /PushMission2Client03.asp
		$a_01_1 = {26 00 50 00 75 00 62 00 6c 00 69 00 63 00 65 00 72 00 3d 00 } //01 00  &Publicer=
		$a_01_2 = {4d 00 41 00 43 00 3d 00 } //01 00  MAC=
		$a_01_3 = {55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 3a 00 20 00 43 00 6c 00 69 00 63 00 6b 00 41 00 64 00 73 00 42 00 79 00 49 00 45 00 } //01 00  User-Agent: ClickAdsByIE
		$a_01_4 = {41 00 63 00 63 00 65 00 70 00 74 00 2d 00 4c 00 61 00 6e 00 67 00 75 00 61 00 67 00 65 00 3a 00 20 00 7a 00 68 00 2d 00 63 00 6e 00 2c 00 7a 00 68 00 3b 00 71 00 3d 00 30 00 2e 00 35 00 } //00 00  Accept-Language: zh-cn,zh;q=0.5
	condition:
		any of ($a_*)
 
}