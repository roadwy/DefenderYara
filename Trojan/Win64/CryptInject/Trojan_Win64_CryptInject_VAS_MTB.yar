
rule Trojan_Win64_CryptInject_VAS_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.VAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 c2 41 fe c2 03 c2 8a 0c 18 41 30 09 49 ff c1 41 80 fa 04 72 e8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}