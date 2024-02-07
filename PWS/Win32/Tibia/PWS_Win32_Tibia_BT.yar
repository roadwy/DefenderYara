
rule PWS_Win32_Tibia_BT{
	meta:
		description = "PWS:Win32/Tibia.BT,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 00 77 00 73 00 32 00 5f 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //01 00  Ews2_32.dll
		$a_01_1 = {26 69 64 65 6e 74 79 66 69 6b 61 74 6f 72 3d } //01 00  &identyfikator=
		$a_01_2 = {62 61 7a 61 3d } //01 00  baza=
		$a_01_3 = {26 77 65 72 73 6a 61 3d } //01 00  &wersja=
		$a_01_4 = {26 77 65 72 5f 73 79 73 3d } //01 00  &wer_sys=
		$a_01_5 = {26 61 63 63 3d } //01 00  &acc=
		$a_01_6 = {26 70 61 73 73 3d } //01 00  &pass=
		$a_01_7 = {26 6e 69 63 6b 3d } //01 00  &nick=
		$a_01_8 = {26 68 65 6c 6d 65 74 3d } //01 00  &helmet=
		$a_01_9 = {26 62 61 63 6b 70 61 63 6b 3d } //01 00  &backpack=
		$a_01_10 = {26 61 6d 75 6c 65 74 3d } //01 00  &amulet=
		$a_01_11 = {26 62 72 6f 6e 3d } //01 00  &bron=
		$a_01_12 = {26 61 72 6d 6f 72 3d } //01 00  &armor=
		$a_01_13 = {26 74 61 72 63 7a 61 3d } //00 00  &tarcza=
	condition:
		any of ($a_*)
 
}