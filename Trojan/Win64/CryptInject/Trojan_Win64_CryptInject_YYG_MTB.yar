
rule Trojan_Win64_CryptInject_YYG_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YYG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 ce 4c 8d 75 bb 49 81 ec ?? ?? ?? ?? 48 89 4d bf 8b 55 bb 31 d0 8b 55 b0 4c 89 d9 2b 55 f8 31 d1 81 c1 6e a9 00 00 48 81 ea 9e 73 00 00 29 d0 4c 89 4d c4 4d 01 c1 48 ff 04 24 83 3c 24 07 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}