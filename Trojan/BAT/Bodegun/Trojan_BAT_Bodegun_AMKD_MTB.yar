
rule Trojan_BAT_Bodegun_AMKD_MTB{
	meta:
		description = "Trojan:BAT/Bodegun.AMKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 0b 16 0c 2b 62 07 08 9a 0d 00 09 6f ?? ?? ?? 0a 13 05 12 05 fe 16 16 00 00 01 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}