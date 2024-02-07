
rule Worm_Win32_Dogkild_A_dll{
	meta:
		description = "Worm:Win32/Dogkild.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 64 72 69 76 65 72 73 5c 70 63 69 64 75 6d 70 2e 73 79 73 } //01 00  \drivers\pcidump.sys
		$a_01_1 = {56 53 4d 45 70 78 6f 6d 70 62 65 55 70 44 62 64 69 66 47 6a 6d 66 42 00 } //01 00  卖䕍硰浯扰啥䑰摢晩橇晭B
		$a_03_2 = {6a 00 6a 00 6a 08 8d 45 90 01 01 50 68 14 20 22 00 ff 75 f4 ff 15 90 01 04 68 d0 07 00 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}