
rule Worm_Win32_Poenon_B{
	meta:
		description = "Worm:Win32/Poenon.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00 20 00 25 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 25 00 20 00 2a 00 20 00 2f 00 52 00 41 00 4e 00 44 00 4f 00 4d 00 } //01 00  net user %username% * /RANDOM
		$a_01_1 = {48 00 69 00 64 00 65 00 4d 00 79 00 49 00 70 00 53 00 72 00 76 00 } //01 00  HideMyIpSrv
		$a_01_2 = {24 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 57 00 69 00 70 00 65 00 2e 00 62 00 61 00 74 00 } //01 00  $windowsWipe.bat
		$a_01_3 = {63 72 65 61 74 65 72 20 6f 66 20 74 68 69 73 } //00 00  creater of this
	condition:
		any of ($a_*)
 
}