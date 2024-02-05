
rule Trojan_Win32_Agent_OJ{
	meta:
		description = "Trojan:Win32/Agent.OJ,SIGNATURE_TYPE_PEHSTR,20 00 20 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 75 70 65 72 66 61 73 74 2e 63 6f 6d 2e 73 61 70 6f 2e 70 74 2f 66 6f 74 6f 73 2e 63 6f 6d } //0a 00 
		$a_01_1 = {63 3a 5c 38 39 35 30 30 34 2e 65 78 65 } //0a 00 
		$a_01_2 = {63 3a 5c 36 30 35 36 34 35 2e 74 78 74 } //01 00 
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00 
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}