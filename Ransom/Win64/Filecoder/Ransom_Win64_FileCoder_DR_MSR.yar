
rule Ransom_Win64_FileCoder_DR_MSR{
	meta:
		description = "Ransom:Win64/FileCoder.DR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {64 65 63 72 79 70 74 20 74 68 65 20 66 69 6c 65 73 20 6f 72 20 62 72 75 74 65 66 6f 72 63 65 20 74 68 65 20 6b 65 79 20 77 69 6c 6c 20 62 65 20 66 75 74 69 6c 65 20 61 6e 64 20 6c 65 61 64 20 74 6f 20 6c 6f 73 73 20 6f 66 20 74 69 6d 65 20 61 6e 64 20 70 72 65 63 69 6f 75 73 20 64 61 74 61 } //decrypt the files or bruteforce the key will be futile and lead to loss of time and precious data  01 00 
		$a_80_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //Go build ID:  01 00 
		$a_80_2 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //-----BEGIN RSA PUBLIC KEY-----  01 00 
		$a_80_3 = {50 41 53 53 57 4f 52 44 } //PASSWORD  00 00 
	condition:
		any of ($a_*)
 
}