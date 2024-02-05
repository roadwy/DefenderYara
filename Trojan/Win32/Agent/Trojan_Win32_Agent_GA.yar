
rule Trojan_Win32_Agent_GA{
	meta:
		description = "Trojan:Win32/Agent.GA,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8a 47 fe 50 e8 90 01 04 83 c4 04 85 c0 0f 8c 90 01 04 8a 4f ff c1 e0 06 51 8b f0 e8 90 01 04 83 c4 04 85 c0 0f 8c 90 01 04 03 f0 8a 07 c1 e6 06 3c 3d 90 00 } //0a 00 
		$a_01_1 = {73 6f 66 74 77 61 72 65 5c 6d 49 43 52 4f 53 4f 46 54 5c 77 49 4e 44 4f 57 53 20 6e 74 5c 63 55 52 52 45 4e 54 76 45 52 53 49 4f 4e 5c 73 56 43 48 4f 53 54 } //0a 00 
		$a_00_2 = {25 73 59 53 54 45 4d 72 4f 4f 54 25 5c 73 59 53 54 45 4d 33 32 5c 53 56 43 48 4f 53 54 2e 45 58 45 20 2d 4b 20 4e 45 54 53 56 43 53 } //01 00 
		$a_00_3 = {76 6e 77 3d 3d } //00 00 
	condition:
		any of ($a_*)
 
}