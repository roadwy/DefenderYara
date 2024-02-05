
rule Trojan_Win32_Agent_PDSK_MTB{
	meta:
		description = "Trojan:Win32/Agent.PDSK!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 65 6d 75 2d 67 61 2e 65 78 65 } //01 00 
		$a_01_1 = {69 70 6c 6f 67 67 65 72 2e 6f 72 67 } //01 00 
		$a_01_2 = {74 72 61 63 6b 2f 67 6c 71 6b 68 7a 6d 70 3f 73 75 62 3d } //01 00 
		$a_01_3 = {5c 70 6f 73 74 62 61 63 6b 73 74 61 74 2e 65 78 65 } //01 00 
		$a_01_4 = {5c 75 70 64 61 74 65 72 33 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}