
rule Trojan_Win64_Jalapeno_DA_MTB{
	meta:
		description = "Trojan:Win64/Jalapeno.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 3a 5c 55 73 65 72 73 5c 44 65 76 65 6c 6f 70 65 72 53 79 73 5c 44 6f 63 75 6d 65 6e 74 73 5c 45 6d 62 61 72 63 61 64 65 72 6f 5c 53 74 75 64 69 6f 5c 50 72 6f 6a 65 63 74 73 5c 44 4c 4c 20 4e 65 77 20 43 6f 6d 70 6c 65 74 61 5c 50 72 6f 6a 65 74 6f 20 43 2b 2b 5c [0-96] 5c 52 65 6c 65 61 73 65 5c [0-1e] 2e 70 64 62 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}