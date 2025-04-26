
rule Trojan_Win64_CryptInject_WFB_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.WFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 b9 14 00 00 00 f7 f9 8b c2 89 44 24 2c 48 63 44 24 2c 48 63 4c 24 28 0f b6 44 04 30 88 44 0c 30 48 63 44 24 2c 0f b6 4c 24 20 88 4c 04 30 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}