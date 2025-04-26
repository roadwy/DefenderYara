
rule Trojan_BAT_Rozena_SPDT_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 0b 7e ?? ?? ?? 0a 07 20 00 10 00 00 1f 40 28 ?? ?? ?? 06 0c 06 16 08 07 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}