
rule Trojan_Win64_CryptInject_YAD_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 41 ff 48 8b c1 49 2b c0 83 e0 1f 0f b6 04 18 41 32 04 09 88 01 49 8d 04 0b 83 e0 1f 0f b6 04 18 41 32 04 0a 88 41 01 48 8d 04 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}