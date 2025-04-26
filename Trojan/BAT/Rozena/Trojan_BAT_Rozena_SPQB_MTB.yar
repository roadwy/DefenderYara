
rule Trojan_BAT_Rozena_SPQB_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 9a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 07 08 11 06 11 07 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 08 11 08 2d d5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}