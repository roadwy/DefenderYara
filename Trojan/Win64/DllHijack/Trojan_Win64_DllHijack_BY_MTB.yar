
rule Trojan_Win64_DllHijack_BY_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 0f b6 0c 08 03 d1 81 e2 ff 00 00 80 7d 0a ff ca 81 ca 00 ff ff ff ff c2 48 63 c2 49 ff c2 42 0f b6 0c 08 41 30 4a ff 49 ff c8 0f 85 } //4
		$a_01_1 = {0f b6 d1 43 0f b6 0c 0b 42 0f b6 04 0a 43 88 04 0b 42 88 0c 0a } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}