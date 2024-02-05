
rule Trojan_BAT_Nanocore_BMN_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.BMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 0b 02 07 8f 04 00 00 01 25 47 03 06 04 6f 90 01 03 0a 5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 96 00 00 00 5f d2 61 d2 52 06 17 58 0a 06 02 8e 69 32 cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}