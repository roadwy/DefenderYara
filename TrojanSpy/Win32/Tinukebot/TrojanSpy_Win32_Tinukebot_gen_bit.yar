
rule TrojanSpy_Win32_Tinukebot_gen_bit{
	meta:
		description = "TrojanSpy:Win32/Tinukebot.gen!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 66 6f 7c 25 64 7c 25 64 7c 25 64 7c 25 64 7c 25 73 7c 25 73 7c 25 64 7c 25 64 } //01 00  info|%d|%d|%d|%d|%s|%s|%d|%d
		$a_03_1 = {25 73 5c 25 73 5c 25 73 5c 25 73 2e 69 6e 69 90 02 30 4d 6f 7a 69 6c 6c 61 90 00 } //01 00 
		$a_03_2 = {62 69 6e 7c 69 6e 74 33 32 90 02 30 00 62 69 6e 7c 69 6e 74 36 34 90 00 } //01 00 
		$a_03_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 02 30 64 6c 6c 68 6f 73 74 2e 65 78 65 90 00 } //01 00 
		$a_03_4 = {00 69 6e 6a 65 63 74 73 00 90 02 30 46 69 72 65 66 6f 78 90 02 30 43 68 72 6f 6d 65 90 00 } //01 00 
		$a_01_5 = {75 73 65 72 5f 70 72 65 66 28 22 6c 61 79 65 72 73 2e 61 63 63 65 6c 65 72 61 74 69 6f 6e 2e 64 69 73 61 62 6c 65 64 22 2c 20 74 72 75 65 29 3b } //01 00  user_pref("layers.acceleration.disabled", true);
		$a_01_6 = {2d 2d 6e 6f 2d 73 61 6e 64 62 6f 78 20 2d 2d 61 6c 6c 6f 77 2d 6e 6f 2d 73 61 6e 64 62 6f 78 2d 6a 6f 62 20 2d 2d 64 69 73 61 62 6c 65 2d 33 64 2d 61 70 69 73 20 2d 2d 64 69 73 61 62 6c 65 2d 67 70 75 20 2d 2d 64 69 73 61 62 6c 65 2d 64 33 64 31 31 20 2d 2d 75 73 65 72 2d 64 61 74 61 2d 64 69 72 3d } //00 00  --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir=
	condition:
		any of ($a_*)
 
}