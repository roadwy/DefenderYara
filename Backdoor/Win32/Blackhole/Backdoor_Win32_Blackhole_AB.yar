
rule Backdoor_Win32_Blackhole_AB{
	meta:
		description = "Backdoor:Win32/Blackhole.AB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {b9 0a 00 00 00 99 f7 f9 } //01 00 
		$a_00_1 = {3d 03 01 00 00 74 2c 85 c0 75 47 } //01 00 
		$a_02_2 = {83 f8 05 0f 87 90 01 01 00 00 00 ff 24 85 90 00 } //01 00 
		$a_00_3 = {42 6c 61 63 6b 20 48 6f 6c 65 09 01 04 20 50 72 6f 66 65 73 } //03 00 
		$a_00_4 = {cd cb b3 f6 5b ba da b6 b4 } //01 00 
		$a_00_5 = {6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 57 69 6e 4f 6c 64 41 70 70 } //00 00 
	condition:
		any of ($a_*)
 
}