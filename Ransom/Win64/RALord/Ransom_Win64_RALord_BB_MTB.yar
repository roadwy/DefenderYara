
rule Ransom_Win64_RALord_BB_MTB{
	meta:
		description = "Ransom:Win64/RALord.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 41 4c 6f 72 64 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 RALord ransomware
		$a_01_1 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_01_2 = {70 6c 65 61 73 65 20 64 6f 20 6e 6f 74 20 74 6f 75 63 68 20 74 68 65 20 66 69 6c 65 73 20 62 65 63 6f 75 73 65 20 77 65 20 63 61 6e 27 74 20 64 65 63 72 79 70 74 20 69 74 20 69 66 20 79 6f 75 20 74 6f 75 63 68 20 69 74 } //1 please do not touch the files becouse we can't decrypt it if you touch it
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}