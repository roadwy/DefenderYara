
rule PWS_Win32_OnLineGames_Q{
	meta:
		description = "PWS:Win32/OnLineGames.Q,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 03 00 "
		
	strings :
		$a_03_0 = {d6 85 c0 0f 84 90 09 10 00 90 02 05 c6 90 02 03 78 88 90 02 03 88 90 02 03 ff 90 00 } //03 00 
		$a_00_1 = {73 65 64 2e 64 72 61 75 47 65 6d 61 47 } //03 00  sed.drauGemaG
		$a_00_2 = {6c 6f 67 69 6e 6e 61 6d 65 3d 64 66 00 } //02 00 
		$a_00_3 = {44 46 54 65 6d 70 3a 25 30 38 78 20 64 77 47 65 74 50 61 73 73 32 41 64 64 72 3a 25 30 38 78 20 64 77 47 65 74 50 61 73 73 32 52 65 74 41 64 64 72 3a 25 30 38 78 } //02 00  DFTemp:%08x dwGetPass2Addr:%08x dwGetPass2RetAddr:%08x
		$a_00_4 = {26 6d 78 64 70 3d 00 00 3f 6d 78 64 75 3d 00 } //02 00 
		$a_00_5 = {64 6f 63 75 6d 65 6e 74 2e 64 6f 6d 61 69 6e 20 3d 20 22 68 61 6e 67 61 6d 65 2e 63 6f 6d 22 } //01 00  document.domain = "hangame.com"
		$a_00_6 = {50 61 73 73 77 6f 72 64 25 33 41 } //01 00  Password%3A
		$a_00_7 = {26 65 61 72 74 68 77 6f 72 6d 32 3d } //00 00  &earthworm2=
	condition:
		any of ($a_*)
 
}