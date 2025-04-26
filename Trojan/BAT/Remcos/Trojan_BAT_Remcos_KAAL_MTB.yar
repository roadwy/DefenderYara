
rule Trojan_BAT_Remcos_KAAL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.KAAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 02 07 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 0b 07 02 6f ?? 00 00 0a fe 04 16 fe 01 13 04 11 04 2c 02 16 0b 00 08 17 58 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}