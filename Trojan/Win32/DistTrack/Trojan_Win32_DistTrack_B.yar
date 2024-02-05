
rule Trojan_Win32_DistTrack_B{
	meta:
		description = "Trojan:Win32/DistTrack.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 20 00 63 00 6f 00 70 00 79 00 20 00 20 00 6e 00 65 00 74 00 } //01 00 
		$a_01_1 = {5c 00 61 00 64 00 6d 00 69 00 6e 00 24 00 5c 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 62 00 61 00 74 00 } //01 00 
		$a_01_2 = {53 70 72 65 61 64 65 72 2e 65 78 65 } //01 00 
		$a_01_3 = {2f 00 63 00 20 00 73 00 70 00 72 00 65 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 41 00 } //01 00 
		$a_01_4 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 3f 00 2f 00 63 00 20 00 73 00 70 00 72 00 65 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_5 = {2a 00 2e 00 74 00 78 00 74 00 3f 00 73 00 68 00 75 00 74 00 74 00 65 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}