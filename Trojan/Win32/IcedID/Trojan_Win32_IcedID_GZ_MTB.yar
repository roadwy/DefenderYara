
rule Trojan_Win32_IcedID_GZ_MTB{
	meta:
		description = "Trojan:Win32/IcedID.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 8b c8 66 89 0d 90 01 04 8b 15 90 01 04 8d 84 12 ae 58 00 00 2b 05 90 01 04 83 c4 04 03 c6 66 a3 90 01 04 0f b7 c0 6b c0 1d 5f 0f b7 c9 5e 03 c1 8b 8c 24 b0 08 00 00 5d 5b 33 cc 90 00 } //01 00 
		$a_00_1 = {73 61 6c 74 5c 77 68 6f 5c 57 68 65 6e 5c 6e 75 6d 62 65 72 53 69 67 68 74 2e 70 64 62 } //00 00  salt\who\When\numberSight.pdb
	condition:
		any of ($a_*)
 
}