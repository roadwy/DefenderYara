
rule Trojan_Win64_Tedy_BAD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 44 24 26 0f b6 44 24 27 c1 e0 04 0f b6 4c 24 26 09 c8 48 8b 4c 24 40 8b 54 24 28 88 04 11 8b 44 24 28 83 c0 01 89 44 24 28 eb } //4
		$a_01_1 = {5f 70 61 79 6c 6f 61 64 5f 69 6e 69 74 } //1 _payload_init
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}