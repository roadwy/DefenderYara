
rule Trojan_Win64_IcedID_DEC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 8d 14 08 49 ff c0 8a 42 40 32 02 88 44 11 40 49 83 f8 20 } //1
		$a_01_1 = {4b 8d 14 08 49 ff c0 8a 42 40 32 02 88 44 11 40 } //1
		$a_01_2 = {42 8a 04 02 02 c2 48 ff c2 c0 c0 03 0f b6 c8 8b c1 83 e1 0f 48 c1 e8 04 42 0f be 04 18 66 42 89 04 53 42 0f be 0c 19 66 42 89 4c 53 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}