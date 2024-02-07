
rule Trojan_Win32_Killav_GP{
	meta:
		description = "Trojan:Win32/Killav.GP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 } //01 00  GbPlugin\
		$a_03_1 = {30 39 2e 3a 34 90 01 11 70 72 69 6e 63 69 70 61 6c 90 00 } //01 00 
		$a_00_2 = {61 00 76 00 67 00 6e 00 73 00 78 00 2e 00 65 00 78 00 65 00 } //01 00  avgnsx.exe
		$a_00_3 = {41 00 56 00 47 00 4e 00 54 00 } //01 00  AVGNT
		$a_00_4 = {53 65 72 76 69 63 65 41 66 74 65 72 49 6e 73 74 61 6c 6c } //00 00  ServiceAfterInstall
	condition:
		any of ($a_*)
 
}