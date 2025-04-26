
rule Trojan_BAT_Rozena_SPAN_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 06 6f ?? ?? ?? 0a 0c 16 08 8e 69 20 00 10 00 00 1f 40 28 ?? ?? ?? 06 0d 16 13 04 08 16 09 6e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}