
rule Ransom_Win64_WormWiper_DA_MTB{
	meta:
		description = "Ransom:Win64/WormWiper.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //Your files have been encrypted  1
		$a_80_1 = {2e 52 41 4e 53 4f 4d 5f 4e 4f 54 45 2e 74 78 74 } //.RANSOM_NOTE.txt  1
		$a_80_2 = {45 6e 63 72 79 70 74 65 64 3a } //Encrypted:  1
		$a_80_3 = {57 69 70 65 72 } //Wiper  1
		$a_80_4 = {52 61 6e 73 6f 6d 77 6f 72 6d } //Ransomworm  1
		$a_80_5 = {50 61 79 6c 6f 61 64 } //Payload  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}