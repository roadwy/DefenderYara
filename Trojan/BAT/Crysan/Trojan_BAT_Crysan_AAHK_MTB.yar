
rule Trojan_BAT_Crysan_AAHK_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AAHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0b 06 16 fe 0e 03 00 20 fc ff ff ff 20 2d 2c b7 a2 20 61 af f7 77 61 20 4c 83 40 d5 40 90 01 01 00 00 00 20 02 00 00 00 fe 0e 03 00 fe 90 01 02 00 00 01 58 00 73 90 01 01 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}