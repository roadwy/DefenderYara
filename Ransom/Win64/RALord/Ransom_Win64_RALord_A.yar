
rule Ransom_Win64_RALord_A{
	meta:
		description = "Ransom:Win64/RALord.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 69 6f 6e 20 66 61 69 6c 65 64 3a 20 } //5 Encryption failed: 
		$a_01_1 = {55 6e 73 61 66 65 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 64 65 74 65 63 74 65 64 20 2d 20 64 65 6c 61 79 69 6e 67 20 } //5 Unsafe environment detected - delaying 
		$a_01_2 = {52 4e 4f 56 41 } //1 RNOVA
		$a_01_3 = {4e 6f 76 61 } //1 Nova
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}