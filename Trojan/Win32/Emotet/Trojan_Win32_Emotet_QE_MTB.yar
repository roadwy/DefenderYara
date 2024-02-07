
rule Trojan_Win32_Emotet_QE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.QE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {6b 65 6a 66 77 75 68 69 65 67 6a 77 68 67 77 75 68 69 34 68 68 65 79 79 66 69 77 67 68 2e 74 78 74 } //03 00  kejfwuhiegjwhgwuhi4hheyyfiwgh.txt
		$a_81_1 = {45 72 69 63 61 20 32 35 20 42 65 72 6c 69 6e } //03 00  Erica 25 Berlin
		$a_81_2 = {64 6c 6c 33 32 73 6d 70 6c 2e 70 64 62 } //03 00  dll32smpl.pdb
		$a_81_3 = {42 74 6f 77 63 74 72 61 6e 73 } //03 00  Btowctrans
		$a_81_4 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //03 00  IsProcessorFeaturePresent
		$a_81_5 = {47 65 74 53 79 73 74 65 6d 54 69 6d 65 41 73 46 69 6c 65 54 69 6d 65 } //03 00  GetSystemTimeAsFileTime
		$a_81_6 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //00 00  LockResource
	condition:
		any of ($a_*)
 
}