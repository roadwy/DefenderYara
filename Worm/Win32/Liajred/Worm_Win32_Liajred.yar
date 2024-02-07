
rule Worm_Win32_Liajred{
	meta:
		description = "Worm:Win32/Liajred,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 53 53 53 53 53 6a ff 51 e8 } //01 00 
		$a_00_1 = {78 00 2d 00 66 00 6c 00 79 00 20 00 69 00 6e 00 20 00 64 00 61 00 20 00 68 00 6f 00 75 00 73 00 65 00 } //01 00  x-fly in da house
		$a_00_2 = {4d 00 53 00 46 00 4c 00 43 00 2e 00 46 00 59 00 53 00 } //01 00  MSFLC.FYS
		$a_00_3 = {4e 00 54 00 4c 00 53 00 2e 00 44 00 59 00 53 00 } //01 00  NTLS.DYS
		$a_00_4 = {43 00 3a 00 5c 00 73 00 6f 00 75 00 6c 00 66 00 6c 00 79 00 } //00 00  C:\soulfly
	condition:
		any of ($a_*)
 
}