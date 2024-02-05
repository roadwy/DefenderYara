
rule Trojan_Win32_Banload_YQM_MTB{
	meta:
		description = "Trojan:Win32/Banload.YQM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 73 69 6e 64 61 72 73 70 65 6e 2e 6f 72 67 2e 62 72 2f 90 02 25 6c 63 2d 61 72 71 75 69 76 6f 73 2f 90 02 15 63 68 90 02 03 72 6d 65 2e 65 78 65 90 00 } //01 00 
		$a_81_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //01 00 
		$a_81_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00 
		$a_81_3 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //00 00 
	condition:
		any of ($a_*)
 
}