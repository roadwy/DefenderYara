
rule Trojan_BAT_CustomLoader_CCCL_MTB{
	meta:
		description = "Trojan:BAT/CustomLoader.CCCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 35 00 00 00 00 04 8d 3a 00 00 01 0a 16 0d 38 16 00 00 00 00 06 09 02 03 09 58 91 05 61 d2 9c 00 09 17 58 0d 05 17 58 10 03 09 04 fe 04 13 04 } //01 00 
		$a_01_1 = {7e 14 00 00 04 38 92 ff ff ff 2a 26 00 02 6f 4d 00 00 0a 00 2a 00 00 00 1b 30 06 00 c8 00 00 00 0b 00 00 11 00 00 7e 1b 00 00 04 38 01 } //01 00 
		$a_01_2 = {26 45 04 00 00 00 00 00 00 00 3d 00 00 00 3d 00 00 00 3d 00 00 00 fe 13 7e 10 00 00 04 6f 4e 00 00 0a 73 4f 00 00 0a fe 13 80 10 00 00 04 00 7e } //00 00 
	condition:
		any of ($a_*)
 
}