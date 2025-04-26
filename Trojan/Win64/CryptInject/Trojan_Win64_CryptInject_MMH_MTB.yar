
rule Trojan_Win64_CryptInject_MMH_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 35 41 0f b6 c0 41 ff c0 2a c1 04 38 41 30 41 ff 41 83 f8 4b 7c cf } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}