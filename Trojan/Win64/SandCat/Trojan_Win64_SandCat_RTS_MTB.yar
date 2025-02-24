
rule Trojan_Win64_SandCat_RTS_MTB{
	meta:
		description = "Trojan:Win64/SandCat.RTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 63 68 65 64 20 62 65 61 63 6f 6e 20 66 61 69 6c 75 72 65 20 74 68 72 65 73 68 6f 6c 64 } //1 Reached beacon failure threshold
		$a_01_1 = {54 65 72 6d 69 6e 61 74 69 6e 67 20 53 61 6e 64 63 61 74 20 41 67 65 6e 74 2e 2e 2e 20 67 6f 6f 64 62 79 65 } //2 Terminating Sandcat Agent... goodbye
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}