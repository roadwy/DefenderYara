
rule Trojan_Win64_CryptInject_D_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 04 ?? ?? 00 00 8b 94 24 ?? ?? 00 00 01 c2 31 ca 88 94 04 ?? ?? 00 00 48 83 c0 01 48 83 f8 12 75 dc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}