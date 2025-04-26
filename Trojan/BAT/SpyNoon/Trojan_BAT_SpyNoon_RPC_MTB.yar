
rule Trojan_BAT_SpyNoon_RPC_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c 08 02 8e 69 3f e1 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}