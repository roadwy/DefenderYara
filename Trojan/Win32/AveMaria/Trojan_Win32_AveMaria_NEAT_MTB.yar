
rule Trojan_Win32_AveMaria_NEAT_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 8d 7c ff ff ff 03 4d 90 0f be 11 8b 85 60 ff ff ff 0f be 4c 05 98 33 d1 8b 85 7c ff ff ff 03 45 90 88 10 eb 99 } //05 00 
		$a_01_1 = {8b 55 90 83 c2 01 89 55 90 8b 45 90 3b 85 64 ff ff ff 7d 53 } //03 00 
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00 
		$a_01_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 45 78 41 } //01 00 
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}