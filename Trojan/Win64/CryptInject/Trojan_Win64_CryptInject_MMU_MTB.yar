
rule Trojan_Win64_CryptInject_MMU_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MMU!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c0 89 85 54 03 00 00 48 63 85 54 03 00 00 48 3b 85 d8 02 00 00 73 2b 48 63 85 54 03 00 00 48 8b 8d 38 03 00 00 0f be 04 01 83 f0 08 83 f0 0c 48 63 8d 54 03 00 00 48 8b 95 38 03 00 00 88 04 0a eb b7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}