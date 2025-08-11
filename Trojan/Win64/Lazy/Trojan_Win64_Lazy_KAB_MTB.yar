
rule Trojan_Win64_Lazy_KAB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 8b 42 08 41 ff c1 48 d3 e8 41 03 c8 41 32 04 12 88 44 14 38 48 ff c2 83 f9 40 72 } //10
		$a_01_1 = {4e 8d 0c 01 48 2b d1 49 ff c9 42 8a 04 0a 41 88 01 49 83 e8 01 75 } //8
		$a_01_2 = {43 0f be 0c 02 49 ff c0 83 c1 20 48 63 d1 48 0f af d0 49 33 d1 48 33 c2 4d 3b c1 7c } //7
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*8+(#a_01_2  & 1)*7) >=25
 
}