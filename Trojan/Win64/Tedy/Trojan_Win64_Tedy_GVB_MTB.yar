
rule Trojan_Win64_Tedy_GVB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 75 72 6c 20 2d 2d 73 69 6c 65 6e 74 20 68 74 74 70 73 3a 2f 2f 66 69 6c 65 73 2e 63 61 74 62 6f 78 2e 6d 6f 65 2f [0-10] 20 2d 2d 6f 75 74 70 75 74 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c [0-10] 20 3e 6e 75 6c 20 32 3e 26 31 } //2
		$a_03_1 = {63 64 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 20 26 26 20 [0-10] 2e 65 78 65 20 [0-10] 2e 73 79 73 20 3e 6e 75 6c 20 32 3e 26 31 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}