
rule Trojan_BAT_Rozena_CXJP_MTB{
	meta:
		description = "Trojan:BAT/Rozena.CXJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 0b 09 11 0b 91 18 59 20 ?? ?? ?? ?? 5f d2 9c 00 11 0b 17 58 13 0b 11 0b 09 8e 69 fe 04 13 0c 11 0c 2d da } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}