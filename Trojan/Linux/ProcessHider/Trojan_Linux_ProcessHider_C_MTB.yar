
rule Trojan_Linux_ProcessHider_C_MTB{
	meta:
		description = "Trojan:Linux/ProcessHider.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 8b 15 90 29 00 00 48 8d 85 f0 fe ff ff 48 89 d6 48 89 c7 e8 7e fa ff ff 85 c0 75 05 e9 5d ff ff ff 90 48 8b 85 e8 fd ff ff 48 8b 4d f8 64 48 33 0c 25 28 00 00 00 } //01 00 
		$a_00_1 = {48 8b 95 d8 fe ff ff 48 8d 85 e0 fe ff ff be 00 01 00 00 48 89 c7 e8 39 fd ff ff 48 85 c0 75 16 48 8b 85 d8 fe ff ff 48 89 c7 e8 d5 fc ff ff b8 00 00 00 00 eb 3d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Linux_ProcessHider_C_MTB_2{
	meta:
		description = "Trojan:Linux/ProcessHider.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 61 5f 66 69 6e 61 6c 69 7a 65 00 5f 4a 76 5f 52 65 67 69 73 74 65 72 43 6c 61 73 73 65 73 00 64 69 72 66 64 00 73 6e 70 72 69 6e 74 66 00 72 65 61 64 6c 69 6e 6b 00 73 74 72 73 70 6e 00 73 74 72 6c 65 6e 00 66 6f 70 65 6e 00 66 67 65 74 73 00 66 63 6c 6f 73 65 00 73 73 63 61 6e 66 00 72 65 61 64 64 69 72 36 34 00 64 6c 73 79 6d 00 } //01 00 
		$a_01_1 = {72 00 66 70 72 69 6e 74 66 00 73 74 72 63 6d 70 00 72 65 61 64 64 69 72 00 6c 69 62 64 6c 2e 73 6f 2e 32 00 6c 69 62 63 2e 73 6f 2e 36 00 5f 65 64 61 74 61 00 5f 5f 62 73 73 5f 73 74 61 72 74 00 5f } //01 00 
		$a_01_2 = {67 65 74 5f 70 72 6f 63 65 73 73 5f 6e 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}