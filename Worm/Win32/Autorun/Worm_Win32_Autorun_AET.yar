
rule Worm_Win32_Autorun_AET{
	meta:
		description = "Worm:Win32/Autorun.AET,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 53 00 42 00 44 00 69 00 73 00 6b 00 } //01 00  USBDisk
		$a_01_1 = {25 73 3a 2f 2f 61 75 74 6f 72 75 6e 2e 65 78 65 } //02 00  %s://autorun.exe
		$a_01_2 = {25 73 3a 2f 2f 61 75 74 6f 72 75 6e 2e 69 6e 66 } //03 00  %s://autorun.inf
		$a_01_3 = {8a 1c 37 32 d2 8d 4d ed c7 45 08 08 00 00 00 84 59 ff 74 04 0a 11 eb 06 8a 01 f6 d0 22 d0 41 41 ff 4d 08 75 ea 88 14 37 47 3b 7d fc 7c d2 } //03 00 
		$a_01_4 = {80 e3 7f eb 1e f6 04 31 40 74 05 80 cb 20 eb 13 80 e3 df eb 0e f6 04 31 20 74 05 80 cb 40 eb 03 80 e3 bf 99 2b c2 d1 f8 85 c0 0f 8f 45 ff ff ff 88 1c 31 41 3b cf 0f 8c 32 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}