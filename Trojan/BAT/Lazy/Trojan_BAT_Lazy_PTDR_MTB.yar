
rule Trojan_BAT_Lazy_PTDR_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 94 00 00 00 38 87 dd ff ff 11 07 38 bc 0a 00 00 80 53 00 00 04 20 31 00 00 00 fe 0e 15 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}