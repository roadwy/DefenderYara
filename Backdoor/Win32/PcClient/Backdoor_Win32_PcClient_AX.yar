
rule Backdoor_Win32_PcClient_AX{
	meta:
		description = "Backdoor:Win32/PcClient.AX,SIGNATURE_TYPE_PEHSTR,11 00 0f 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 4b 65 65 70 2d 41 6c 69 76 65 } //02 00 
		$a_01_1 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 7a 68 2d 63 6e } //0a 00 
		$a_01_2 = {26 47 61 6d 65 4e 61 6d 65 3d 25 73 26 4d 61 63 3d 25 73 } //03 00 
		$a_01_3 = {42 72 61 7a 69 6c 5c 70 63 43 6c 69 65 6e 74 2e 69 6e 69 } //03 00 
		$a_01_4 = {25 73 25 73 2f 25 73 5f 25 64 2e 7a 69 70 } //00 00 
	condition:
		any of ($a_*)
 
}