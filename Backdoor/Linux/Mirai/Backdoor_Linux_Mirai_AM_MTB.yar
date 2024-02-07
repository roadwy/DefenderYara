
rule Backdoor_Linux_Mirai_AM_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AM!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 69 72 64 72 6f 70 6d 61 6c 77 61 72 65 } //01 00  airdropmalware
		$a_00_1 = {54 73 75 6e 61 6d 69 } //02 00  Tsunami
		$a_00_2 = {42 6f 74 6e 65 74 20 4d 61 64 65 20 42 79 20 67 72 65 65 6b 2e 48 65 6c 69 6f 73 2c 20 61 6e 64 20 54 68 61 72 33 73 65 6c 6c 65 72 } //00 00  Botnet Made By greek.Helios, and Thar3seller
	condition:
		any of ($a_*)
 
}