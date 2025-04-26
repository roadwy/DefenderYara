
rule Trojan_Win64_Lazy_RW_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 00 41 b8 81 00 00 00 89 c2 4c 89 c1 41 89 c0 41 80 e0 0f c0 ea 04 45 8d 48 30 45 8d 58 37 41 80 f8 0a 45 0f b6 c1 45 0f b6 cb 45 0f 42 c8 44 88 4c 0c 26 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Lazy_RW_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 04 b7 48 05 14 01 00 00 48 89 84 24 f0 00 00 00 8b 40 fc 89 84 24 ac 00 00 00 48 6b c6 18 48 8d 14 07 48 83 c2 20 48 89 94 24 f8 00 00 00 48 8b 42 f8 48 8d 8c 24 d0 00 00 00 48 89 41 10 } //1
		$a_01_1 = {4c 61 7a 79 20 69 6e 73 74 61 6e 63 65 20 68 61 73 20 70 72 65 76 69 6f 75 73 6c 79 20 62 65 65 6e 20 70 6f 69 73 6f 6e 65 64 4f 6e 63 65 } //1 Lazy instance has previously been poisonedOnce
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}