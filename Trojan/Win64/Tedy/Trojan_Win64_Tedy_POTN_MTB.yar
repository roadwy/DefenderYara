
rule Trojan_Win64_Tedy_POTN_MTB{
	meta:
		description = "Trojan:Win64/Tedy.POTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_80_0 = {5b 48 6f 6c 6c 6f 77 5d 20 53 74 61 72 74 69 6e 67 20 68 6f 6c 6c 6f 77 69 6e 67 2e 2e 2e } //[Hollow] Starting hollowing...  5
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6b 00 20 00 6e 00 65 00 74 00 73 00 76 00 63 00 73 00 00 00 00 00 6e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 00 00 00 4d 5a } //5
	condition:
		((#a_80_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}