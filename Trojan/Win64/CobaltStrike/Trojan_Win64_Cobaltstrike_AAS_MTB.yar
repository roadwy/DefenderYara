
rule Trojan_Win64_Cobaltstrike_AAS_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 89 d1 4d 69 c9 39 8e e3 38 49 c1 e9 22 45 01 c9 47 8d 0c c9 41 89 d2 45 29 ca 4c 8b 8d f8 07 00 00 47 0f b6 0c 11 45 32 0c 10 4c 8d 05 63 97 04 00 46 88 0c 02 ff c2 83 fa 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}