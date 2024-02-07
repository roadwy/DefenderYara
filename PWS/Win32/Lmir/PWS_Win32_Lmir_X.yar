
rule PWS_Win32_Lmir_X{
	meta:
		description = "PWS:Win32/Lmir.X,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {61 64 76 61 c7 44 24 90 01 01 70 69 33 32 c7 44 24 90 01 01 2e 64 6c 6c 90 00 } //04 00 
		$a_01_1 = {2b 7d 08 8b cf 8b 75 08 eb 05 80 36 6e 46 49 0b c9 75 f7 6a 00 8d 45 f8 50 57 ff 75 08 ff 75 fc } //01 00 
		$a_01_2 = {c7 07 0d 0a 0d 0a 83 c7 04 c6 07 00 } //01 00 
		$a_01_3 = {66 69 6c 74 72 65 73 25 64 2e 73 61 76 } //01 00  filtres%d.sav
		$a_01_4 = {66 6f 65 6d 61 6e 25 64 2e 73 61 76 } //02 00  foeman%d.sav
		$a_01_5 = {2e 64 6c 6c 00 49 6e 73 74 48 6f 6f 6b 50 72 6f 63 00 55 6e 49 6e 73 74 48 6f 6f 6b 50 72 6f 63 } //00 00  搮汬䤀獮䡴潯偫潲c湕湉瑳潈歯牐捯
	condition:
		any of ($a_*)
 
}