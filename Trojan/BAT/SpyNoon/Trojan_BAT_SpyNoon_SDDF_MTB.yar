
rule Trojan_BAT_SpyNoon_SDDF_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SDDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 09 17 58 0d } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}