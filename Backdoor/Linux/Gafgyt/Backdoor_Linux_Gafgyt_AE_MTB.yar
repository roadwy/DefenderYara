
rule Backdoor_Linux_Gafgyt_AE_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {00 73 79 6e 00 72 73 74 00 66 69 6e 00 61 63 6b 00 70 73 68 00 55 44 50 00 54 43 50 00 53 54 4f 50 00 2f 00 90 09 11 00 3a 90 0f 03 00 00 28 6e 75 6c 6c 29 00 61 6c 6c 00 2c 90 00 } //02 00 
		$a_02_1 = {48 8b 45 e8 48 89 85 d0 fe ff ff 48 c7 85 c8 fe ff ff 90 02 05 48 c7 85 c0 fe ff ff 04 00 00 00 fc 48 8b b5 d0 fe ff ff 48 8b bd c8 fe ff ff 48 8b 8d c0 fe ff ff f3 a6 0f 97 c2 0f 92 c0 89 d1 28 c1 89 c8 0f be c0 85 c0 75 0e 48 8b 45 d8 0f b6 50 0d 83 ca 08 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}