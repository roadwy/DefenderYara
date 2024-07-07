
rule Trojan_Win64_CryptInject_SIC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.SIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b 00 89 45 c8 41 0f b6 40 90 01 01 88 45 cc 80 7a 0a 00 74 19 49 8b c9 0f 1f 00 8d 41 34 30 04 0a 48 ff c1 48 83 f9 09 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}