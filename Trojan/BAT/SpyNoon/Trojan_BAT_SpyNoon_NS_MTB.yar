
rule Trojan_BAT_SpyNoon_NS_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f e7 00 00 0a 07 1f 10 8d 24 00 00 01 25 d0 0a 01 00 04 28 99 00 00 0a 6f e8 00 00 0a 06 07 6f e9 00 00 0a 17 73 6c 00 00 0a 0c 08 02 16 02 8e 69 6f ea 00 00 0a 08 6f eb 00 00 0a 06 28 bf 01 00 06 0d 09 } //3
		$a_01_1 = {55 53 42 57 61 6c 6c 65 74 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 USBWallet.g.resources
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}