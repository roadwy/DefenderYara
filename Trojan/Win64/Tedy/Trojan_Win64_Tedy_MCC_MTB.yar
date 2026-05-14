
rule Trojan_Win64_Tedy_MCC_MTB{
	meta:
		description = "Trojan:Win64/Tedy.MCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 8b c3 8b c1 ff c1 99 41 f7 f9 48 63 c2 8a 04 38 41 30 00 49 ff c0 3b ce 7c e8 } //5
		$a_01_1 = {4c 2b c8 4c 8b c0 8b c2 ff c2 83 e0 03 42 8a 04 28 43 32 04 01 41 88 00 49 ff c0 81 fa f0 04 00 00 7c e3 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}