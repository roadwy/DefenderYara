
rule Trojan_Win64_CryptInject_KLL_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.KLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 4d 2b c1 48 8d 4c 24 28 44 8b d0 4f 8d 0c 18 44 8b c0 0f 1f 80 90 01 04 48 8b c2 48 8d 49 01 83 e0 03 48 ff c2 0f b6 44 04 20 41 32 04 09 88 41 ff 49 83 e8 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}