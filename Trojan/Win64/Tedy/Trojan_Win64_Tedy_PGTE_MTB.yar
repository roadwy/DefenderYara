
rule Trojan_Win64_Tedy_PGTE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PGTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 38 33 2e 32 31 37 2e 32 30 39 2e 31 36 39 3a 35 35 35 33 2f 66 69 6c 65 73 2f [0-0f] 2e [0-0a] 76 65 63 74 6f 72 20 74 6f 6f 20 6c 6f 6e 67 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}