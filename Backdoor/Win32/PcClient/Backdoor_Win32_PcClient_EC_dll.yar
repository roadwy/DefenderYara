
rule Backdoor_Win32_PcClient_EC_dll{
	meta:
		description = "Backdoor:Win32/PcClient.EC!dll,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {99 b9 ff 00 00 00 f7 f9 80 fa 20 } //01 00 
		$a_01_1 = {50 63 43 6c 69 65 6e 74 2e 64 6c 6c } //01 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 64 25 73 } //01 00 
		$a_01_3 = {25 73 3f 6d 61 63 3d 25 73 26 69 3d 31 26 74 3d 25 36 64 } //00 00 
	condition:
		any of ($a_*)
 
}