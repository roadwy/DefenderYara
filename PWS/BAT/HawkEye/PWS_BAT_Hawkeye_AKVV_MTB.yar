
rule PWS_BAT_Hawkeye_AKVV_MTB{
	meta:
		description = "PWS:BAT/Hawkeye.AKVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 0a 06 8e 69 8d 22 00 00 01 0b 16 0c 2b 0a 07 08 06 08 91 9d 08 17 58 0c 08 07 8e 69 32 f0 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //01 00 
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}