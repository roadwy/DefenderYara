
rule PWS_Win32_QQpass_FP{
	meta:
		description = "PWS:Win32/QQpass.FP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 a4 26 c6 45 a5 71 c6 45 a6 71 c6 45 a7 70 c6 45 a8 61 c6 45 a9 73 c6 45 aa 73 c6 45 ab 77 c6 45 ac 6f c6 45 ad 72 c6 45 ae 64 c6 45 af 3d 88 5d b0 ff d7 } //01 00 
		$a_03_1 = {80 ea 03 88 94 05 98 fb ff ff 40 3b c7 7e eb 90 09 06 00 8a 90 90 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_QQpass_FP_2{
	meta:
		description = "PWS:Win32/QQpass.FP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 77 77 73 3d 32 32 34 3a 36 31 35 38 35 31 34 3c 37 31 35 37 33 32 7a 68 65 } //01 00 
		$a_01_1 = {c6 85 04 e4 fd ff 71 c6 85 05 e4 fd ff 71 c6 85 06 e4 fd ff 2e c6 85 07 e4 fd ff 65 c6 85 08 e4 fd ff 78 c6 85 09 e4 fd ff 65 } //01 00 
		$a_01_2 = {c6 85 fc dc fd ff 5c c6 85 fd dc fd ff 51 c6 85 fe dc fd ff 51 c6 85 ff dc fd ff 5c c6 85 00 dd fd ff 52 c6 85 01 dd fd ff 65 c6 85 02 dd fd ff 67 c6 85 03 dd fd ff 69 c6 85 04 dd fd ff 73 } //00 00 
	condition:
		any of ($a_*)
 
}