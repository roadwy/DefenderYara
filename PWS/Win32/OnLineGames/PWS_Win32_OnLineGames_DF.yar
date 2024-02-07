
rule PWS_Win32_OnLineGames_DF{
	meta:
		description = "PWS:Win32/OnLineGames.DF,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 64 6d 6d 6d 2e 76 78 64 } //01 00  mdmmm.vxd
		$a_01_1 = {56 65 72 43 4c 53 49 44 2e 65 78 65 } //01 00  VerCLSID.exe
		$a_01_2 = {57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 00 00 00 00 ff ff ff ff 2c 00 00 00 43 4c 53 49 44 5c 7b 39 32 42 31 45 38 31 36 2d 32 43 45 46 2d 34 33 34 35 2d 38 37 34 38 2d 37 36 39 39 43 37 43 39 39 33 35 46 7d 00 00 00 00 ff ff ff ff 0f 00 00 00 5c 49 6e 50 72 6f 63 53 65 72 76 65 } //00 00 
	condition:
		any of ($a_*)
 
}