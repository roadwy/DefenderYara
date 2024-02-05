
rule Backdoor_Win32_Skpark_A_MTB{
	meta:
		description = "Backdoor:Win32/Skpark.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 70 6f 73 74 } //01 00 
		$a_01_1 = {6c 61 73 74 5f 73 65 65 6e } //01 00 
		$a_01_2 = {73 68 65 6c 6c 5f 65 78 65 63 } //01 00 
		$a_01_3 = {53 4b 38 50 41 52 4b } //01 00 
		$a_01_4 = {6d 61 63 61 72 6f 6f 6e 3d } //01 00 
		$a_01_5 = {2f 73 74 61 67 65 30 } //01 00 
		$a_01_6 = {2f 73 74 61 67 65 31 } //00 00 
	condition:
		any of ($a_*)
 
}