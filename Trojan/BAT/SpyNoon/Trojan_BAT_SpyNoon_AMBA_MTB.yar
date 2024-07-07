
rule Trojan_BAT_SpyNoon_AMBA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 1d 11 1a 59 13 1e 07 11 18 11 1e 11 16 5d d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}