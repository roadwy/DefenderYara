
rule TrojanDownloader_BAT_Injector_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Injector.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 07 03 07 91 2b 90 01 01 00 2b 90 01 01 07 25 17 59 0b 16 fe 90 01 01 0c 2b 90 01 01 00 2b 90 01 01 08 2d 90 01 01 2b 90 01 01 2b 90 00 } //01 00 
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00 
		$a_01_2 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_3 = {49 6e 76 6f 6b 65 } //00 00 
	condition:
		any of ($a_*)
 
}