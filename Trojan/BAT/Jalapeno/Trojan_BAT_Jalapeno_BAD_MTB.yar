
rule Trojan_BAT_Jalapeno_BAD_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 03 11 01 ?? ?? 00 00 0a 38 00 00 00 00 dd 1e 00 00 00 11 03 39 11 00 00 00 38 00 00 00 00 11 03 ?? ?? 00 00 0a 38 00 00 00 00 dc 38 00 00 00 00 11 01 ?? ?? 00 00 0a 13 04 38 2b 00 00 00 11 00 11 02 16 1a ?? ?? 00 00 0a 1a 3b 0b 00 00 00 38 00 00 00 00 73 1c 00 00 0a 7a 11 00 16 73 1d 00 00 0a 13 03 38 95 ff ff ff dd 41 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}