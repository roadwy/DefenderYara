
rule Trojan_Win64_CryptInject_BAX_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.BAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 01 d2 44 88 51 01 45 0f b6 d2 42 0f b6 74 11 90 01 01 40 88 74 01 02 42 88 54 11 02 02 54 01 02 0f b6 d2 0f b6 44 11 90 01 01 42 32 04 1b 43 88 04 18 49 83 c3 01 4d 39 d9 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}