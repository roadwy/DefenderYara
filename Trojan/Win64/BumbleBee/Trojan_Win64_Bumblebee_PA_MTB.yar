
rule Trojan_Win64_Bumblebee_PA_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 01 81 b8 03 00 00 49 8b 90 02 02 08 49 8b 90 02 02 70 02 00 00 48 69 88 40 01 00 00 90 02 04 48 31 8a d0 03 00 00 4d 8b 90 02 02 58 04 00 00 49 63 90 02 02 0c 06 00 00 49 63 90 02 02 08 06 00 00 41 8b 0c 80 41 31 0c 90 90 41 8b 90 02 02 1c 06 00 00 23 90 01 01 7d 90 00 } //01 00 
		$a_01_1 = {4f 62 6f 58 62 51 58 4d 50 42 } //00 00  OboXbQXMPB
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Bumblebee_PA_MTB_2{
	meta:
		description = "Trojan:Win64/Bumblebee.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {41 0f b6 49 90 01 01 41 0f b6 14 00 49 83 c0 04 49 8b 81 90 01 04 0f af d1 49 63 49 90 01 01 88 14 01 b8 90 01 04 41 2b 41 90 01 01 41 01 81 90 01 04 b8 90 01 04 41 8b 90 00 } //01 00 
		$a_03_1 = {41 33 ca 41 ff 41 90 01 01 2b c1 41 01 41 90 01 01 41 8b 41 90 01 01 83 f0 01 83 c0 df 03 c2 41 2b 91 90 01 04 41 01 81 90 01 04 83 ea 90 01 01 41 8b 41 90 00 } //01 00 
		$a_03_2 = {41 8b ca 41 33 89 90 01 04 41 ff 41 50 2b c1 41 01 41 90 01 01 41 8b 41 90 01 01 83 f0 01 83 c0 df 03 c2 41 2b 91 90 01 04 41 01 81 90 01 04 83 ea 90 01 01 41 8b 41 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 30 47 05 80 5c 26 } //00 00 
	condition:
		any of ($a_*)
 
}