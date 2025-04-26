
rule Trojan_BAT_Jalapeno_SDGB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SDGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 20 ?? ?? ?? 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 08 20 ?? ?? ?? 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 28 ?? 00 00 0a 09 07 16 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0a de 0a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}