
rule Trojan_Win64_StealC_KB_MTB{
	meta:
		description = "Trojan:Win64/StealC.KB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 0f b6 1c 16 45 31 d9 44 88 0c 0b 48 ff c1 48 89 d8 4c 89 d2 49 39 c8 7e 26 } //5
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 5f 64 61 74 61 2e 6c 7a 6d 61 } //1 encrypted_data.lzma
		$a_81_2 = {6b 65 79 2e 62 69 6e } //1 key.bin
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=7
 
}