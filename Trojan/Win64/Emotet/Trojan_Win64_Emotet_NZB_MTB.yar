
rule Trojan_Win64_Emotet_NZB_MTB{
	meta:
		description = "Trojan:Win64/Emotet.NZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c2 48 63 c8 48 63 05 90 01 04 0f b6 14 39 48 63 0d 90 01 04 32 14 2b 49 0f af c9 49 2b c8 48 83 e9 02 48 0f af c8 48 63 05 90 01 04 48 2b c8 49 2b c8 49 03 c9 48 8d 04 4b 48 ff c3 42 88 14 18 44 3b d6 72 95 90 00 } //1
		$a_01_1 = {3c 57 79 4f 34 76 48 4a 4e 6e 32 45 3c 3c 31 42 4a 48 4c 61 46 28 43 79 35 35 4e 4f 77 3f 3c 55 } //1 <WyO4vHJNn2E<<1BJHLaF(Cy55NOw?<U
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}