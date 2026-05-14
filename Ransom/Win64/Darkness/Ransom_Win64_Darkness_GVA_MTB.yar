
rule Ransom_Win64_Darkness_GVA_MTB{
	meta:
		description = "Ransom:Win64/Darkness.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 64 61 72 6b 6e 65 73 73 } //1 .darkness
		$a_01_1 = {53 6f 6c 61 6e 61 } //1 Solana
		$a_01_2 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_01_3 = {59 4f 55 52 20 46 49 4c 45 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //1 YOUR FILE HAVE BEEN ENCRYPTED
		$a_01_4 = {50 41 59 20 42 59 20 54 48 45 20 53 50 45 43 49 46 49 45 44 20 54 49 4d 45 2c 20 4f 54 48 45 52 57 49 53 45 20 59 4f 55 20 57 49 4c 4c 20 53 55 46 46 45 52 20 54 48 45 20 43 4f 4e 53 45 51 55 45 4e 43 45 53 } //1 PAY BY THE SPECIFIED TIME, OTHERWISE YOU WILL SUFFER THE CONSEQUENCES
		$a_01_5 = {54 68 65 20 74 6f 6f 6c 20 77 6f 72 6b 73 2e 20 59 6f 75 20 63 61 6e 20 74 65 73 74 20 69 74 20 6f 6e 20 32 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 20 66 69 72 73 74 2e } //1 The tool works. You can test it on 2 files for free first.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}