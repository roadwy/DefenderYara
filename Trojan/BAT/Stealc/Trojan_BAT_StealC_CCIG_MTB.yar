
rule Trojan_BAT_StealC_CCIG_MTB{
	meta:
		description = "Trojan:BAT/StealC.CCIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 17 73 ?? ?? ?? ?? 0d 00 09 03 16 03 8e 69 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 00 de 0b 09 2c 07 09 6f ?? 00 00 0a 00 dc 08 6f ?? 00 00 0a 13 04 de 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}