
rule Trojan_Win64_CryptInject_GKV_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.GKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d6 89 0d ec 09 0a 00 0f b6 df 89 d0 0f b6 df 4c 8b 4d c2 8b 5d c4 4d 09 ca 89 45 dc 0f b6 da 81 ea ?? ?? ?? ?? 31 55 ce 4c 89 55 d5 21 c3 31 55 f9 09 c1 09 5d d0 21 4d c5 89 5d fc 01 c0 48 ff 04 24 48 83 3c 24 09 0f 8e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}