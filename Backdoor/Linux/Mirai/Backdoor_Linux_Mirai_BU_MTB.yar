
rule Backdoor_Linux_Mirai_BU_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {8b 5c 0a 04 0f b7 43 2c 8b 53 1c 66 85 c0 0f b7 f8 0f 84 bd 00 00 00 0f b7 73 2a 01 da 31 c9 31 ed c7 44 24 0c ff ff ff ff } //01 00 
		$a_00_1 = {2f 64 65 76 2f 77 61 74 63 68 64 6f 67 } //01 00  /dev/watchdog
		$a_00_2 = {2f 64 65 76 2f 6d 69 73 63 2f 77 61 74 63 68 64 6f 67 } //00 00  /dev/misc/watchdog
	condition:
		any of ($a_*)
 
}