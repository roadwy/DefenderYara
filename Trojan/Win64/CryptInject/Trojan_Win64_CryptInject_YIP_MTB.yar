
rule Trojan_Win64_CryptInject_YIP_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 03 cb 0f b6 c1 8a 94 05 ?? ?? ?? ?? 43 32 14 11 41 88 12 4d 03 d6 49 2b f6 75 } //1
		$a_01_1 = {49 2b c2 83 e0 0f 8a 0c 08 41 32 09 41 32 c8 41 ff c0 f6 d1 41 88 09 49 ff c1 44 3b c2 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}