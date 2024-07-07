
rule Ransom_MSIL_FileCoder_BB_MSR{
	meta:
		description = "Ransom:MSIL/FileCoder.BB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_80_0 = {42 42 20 72 61 6e 73 6f 6d 77 61 72 65 } //BB ransomware  2
		$a_80_1 = {2e 65 6e 63 72 79 70 74 65 64 62 79 42 42 } //.encryptedbyBB  2
		$a_80_2 = {48 65 6c 6c 6f 21 20 49 27 6d 20 61 20 42 42 2c 20 61 6e 64 20 49 6d 20 65 6e 63 72 79 70 74 20 79 6f 75 72 } //Hello! I'm a BB, and Im encrypt your  2
		$a_80_3 = {50 6c 65 61 73 65 20 67 69 76 65 20 6d 65 20 61 20 42 54 43 20 54 6f 20 61 64 64 72 65 73 73 3a } //Please give me a BTC To address:  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1) >=7
 
}