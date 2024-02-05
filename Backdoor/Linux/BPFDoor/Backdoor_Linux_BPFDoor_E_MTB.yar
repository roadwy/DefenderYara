
rule Backdoor_Linux_BPFDoor_E_MTB{
	meta:
		description = "Backdoor:Linux/BPFDoor.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 64 6d 74 6d 70 66 6c 75 73 68 } //01 00 
		$a_00_1 = {70 69 63 6b 75 70 20 2d 6c 20 2d 74 20 66 69 66 6f 20 2d 75 } //01 00 
		$a_00_2 = {64 62 75 73 2d 64 61 65 6d 6f 6e 20 2d 2d 73 79 73 74 65 6d } //02 00 
		$a_03_3 = {ff ff 48 83 c0 14 48 89 85 90 01 02 ff ff 48 8b 85 90 01 02 ff ff 48 83 c0 08 48 89 85 90 01 02 ff ff eb 90 01 01 48 8b 85 90 01 02 ff ff 48 83 c0 14 48 89 85 90 01 02 ff ff 48 8b 85 90 01 02 ff ff 48 83 c0 08 48 89 85 90 01 02 ff ff 90 00 } //02 00 
		$a_03_4 = {55 89 e5 83 ec 18 c7 45 e8 3c 08 0a 49 c7 45 ec 00 00 00 00 c7 45 f0 3c 08 0a 49 c7 45 f4 00 00 00 00 83 ec 08 8d 45 e8 50 ff 75 08 e8 90 02 05 83 c4 10 c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}