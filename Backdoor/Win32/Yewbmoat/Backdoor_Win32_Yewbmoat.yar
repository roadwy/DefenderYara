
rule Backdoor_Win32_Yewbmoat{
	meta:
		description = "Backdoor:Win32/Yewbmoat,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 0a 00 00 03 00 "
		
	strings :
		$a_00_0 = {ff ff ff ff 0d 00 00 00 66 6d 69 64 65 70 6c 6f 79 2e 65 78 65 00 00 00 ff ff ff ff } //03 00 
		$a_00_1 = {ff ff ff ff 0c 00 00 00 69 61 73 72 65 63 73 74 2e 65 78 65 00 00 00 00 ff ff } //03 00 
		$a_00_2 = {77 65 62 79 61 74 6f 6d 00 00 00 00 55 8b ec 33 c0 55 68 } //02 00 
		$a_01_3 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //01 00 
		$a_00_4 = {6b 69 6c 6c 5f 62 65 67 69 6e } //01 00  kill_begin
		$a_00_5 = {6b 69 6c 6c 5f 65 6e 64 } //01 00  kill_end
		$a_00_6 = {64 65 6c 65 74 65 5f 62 65 67 69 6e } //01 00  delete_begin
		$a_00_7 = {64 65 6c 65 74 65 5f 65 6e 64 } //01 00  delete_end
		$a_00_8 = {26 73 74 61 74 75 73 3d 31 26 76 65 72 73 69 6f 6e 3d } //01 00  &status=1&version=
		$a_00_9 = {75 73 72 73 76 70 69 61 2e 69 6e 69 } //00 00  usrsvpia.ini
	condition:
		any of ($a_*)
 
}