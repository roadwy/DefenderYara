
rule Trojan_Win64_Remcos_NR_MTB{
	meta:
		description = "Trojan:Win64/Remcos.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 65 78 65 63 75 74 65 20 74 68 65 20 2e 62 61 74 20 66 69 6c 65 } //1 Failed to execute the .bat file
		$a_01_1 = {63 6d 64 2f 43 73 74 61 72 74 2f 42 } //1 cmd/Cstart/B
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 74 68 65 20 66 69 6c 65 73 72 63 } //1 Failed to download the filesrc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}