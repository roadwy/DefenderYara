
rule Backdoor_Win32_Fledrots_A{
	meta:
		description = "Backdoor:Win32/Fledrots.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 70 f1 00 00 68 12 01 00 00 e8 90 01 04 50 e8 90 01 04 eb cd 90 00 } //01 00 
		$a_01_1 = {70 69 6e 67 2e 70 68 70 } //01 00  ping.php
		$a_01_2 = {69 6d 67 6f 6e 00 } //01 00  浩潧n
		$a_01_3 = {26 72 73 74 3d 31 } //00 00  &rst=1
	condition:
		any of ($a_*)
 
}