
rule Trojan_BAT_Lazy_PTEN_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 2b f6 17 0d 16 13 12 38 1a ff ff ff 28 ?? 01 00 06 13 08 11 08 2c 08 1c 13 12 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}