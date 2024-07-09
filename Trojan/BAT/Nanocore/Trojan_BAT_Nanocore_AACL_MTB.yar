
rule Trojan_BAT_Nanocore_AACL_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AACL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1e 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1a 13 07 38 ?? fe ff ff 1f 0c 13 07 38 ?? fe ff ff 07 17 d6 0b 16 13 07 38 ?? fe ff ff 07 08 fe 04 13 05 11 05 2d 08 18 13 07 38 ?? fe ff ff 1c 2b f6 02 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}