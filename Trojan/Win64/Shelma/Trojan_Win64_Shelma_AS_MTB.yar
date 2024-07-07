
rule Trojan_Win64_Shelma_AS_MTB{
	meta:
		description = "Trojan:Win64/Shelma.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 01 c8 4d 63 c8 44 0f be 42 ff 45 8d 04 58 4d 63 c0 4f 8d 04 98 49 c1 e0 04 4d 01 c8 47 8b 04 82 45 89 c1 41 c1 f9 03 41 83 e1 01 44 88 0c 81 } //1
		$a_01_1 = {41 39 c0 7e 0d 44 8a 0c 02 44 30 0c 01 48 ff c0 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}