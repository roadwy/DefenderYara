
rule Trojan_BAT_Rozena_SPDI_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 0a 06 28 ?? ?? ?? 0a 0b 72 d4 04 00 70 0c 28 ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 0d 07 09 28 ?? ?? ?? 06 13 04 16 11 04 8e 69 7e 01 00 00 04 7e 02 00 00 04 28 ?? ?? ?? 06 13 05 11 04 16 11 05 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}