
rule TrojanDownloader_BAT_Rhadamanthys_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/Rhadamanthys.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {16 0a 03 8e 69 17 59 0b 38 } //02 00 
		$a_01_1 = {03 06 91 0c 03 06 03 07 91 9c 03 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}