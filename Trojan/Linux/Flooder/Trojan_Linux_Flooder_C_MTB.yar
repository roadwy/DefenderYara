
rule Trojan_Linux_Flooder_C_MTB{
	meta:
		description = "Trojan:Linux/Flooder.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 74 61 72 74 69 6e 67 20 46 6c 6f 6f 64 } //01 00  Starting Flood
		$a_00_1 = {62 61 63 6b 64 6f 6f 72 2e 63 } //01 00  backdoor.c
		$a_00_2 = {77 67 65 74 20 2d 71 48 89 85 70 fe ff ff 48 b8 20 2d 2d 64 65 6c 65 74 48 89 85 78 fe ff ff 48 b8 65 2d 61 66 74 65 72 20 48 89 85 80 fe ff ff 48 b8 68 74 74 70 73 3a 2f 2f 48 89 85 88 fe ff ff 48 b8 67 72 61 62 69 66 79 2e 48 89 85 90 fe ff ff 48 b8 6c 69 6e 6b 2f 4b 53 4e } //00 00 
	condition:
		any of ($a_*)
 
}