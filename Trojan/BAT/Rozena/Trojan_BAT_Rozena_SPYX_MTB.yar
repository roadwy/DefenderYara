
rule Trojan_BAT_Rozena_SPYX_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPYX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 0b 7e ?? ?? ?? 0a 20 00 10 00 00 20 00 30 00 00 1f 40 28 ?? ?? ?? 06 0c 06 16 08 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}