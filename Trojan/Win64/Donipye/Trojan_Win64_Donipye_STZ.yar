
rule Trojan_Win64_Donipye_STZ{
	meta:
		description = "Trojan:Win64/Donipye.STZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 48 8d 4c 90 01 02 48 03 c8 8d 42 90 01 01 30 01 ff c2 8b 44 90 01 02 3b d0 72 e7 90 00 } //01 00 
		$a_02_1 = {42 54 52 45 45 2e 64 6c 6c 90 02 10 53 76 63 68 6f 73 74 50 75 73 68 53 65 72 76 69 63 65 47 6c 6f 62 61 6c 73 90 00 } //01 00 
		$a_03_2 = {7d 7e 7c 7e c7 44 90 01 02 78 6c 3e 7b 66 c7 44 90 01 02 62 74 90 00 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}