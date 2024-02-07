
rule PWS_Win32_Zhengtu_B_dll{
	meta:
		description = "PWS:Win32/Zhengtu.B!dll,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 02 e9 6a 04 68 00 30 00 00 8b 4b 18 83 c1 05 51 6a 00 ff 15 } //01 00 
		$a_01_1 = {25 73 5c 64 61 74 61 5c 66 6d 6f 64 65 78 2e 64 6c 6c 31 } //01 00  %s\data\fmodex.dll1
		$a_01_2 = {7a 68 65 6e 67 74 75 32 2e 64 61 74 } //01 00  zhengtu2.dat
		$a_01_3 = {70 61 74 63 68 75 70 64 61 74 65 2e 65 78 65 } //01 00  patchupdate.exe
		$a_01_4 = {33 36 30 74 72 61 79 2e 65 78 65 } //00 00  360tray.exe
	condition:
		any of ($a_*)
 
}