
rule Backdoor_BAT_DCRat_SPF_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.SPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {36 63 39 31 35 36 33 34 2d 34 64 33 65 2d 34 33 32 35 2d 62 38 39 30 2d 64 38 65 32 66 31 61 33 32 34 34 66 } //2 6c915634-4d3e-4325-b890-d8e2f1a3244f
		$a_01_1 = {58 49 71 63 6a 78 6d 76 53 4e 4f 52 44 64 4f 57 33 53 5a 35 6b 6b 38 76 4e 7a 6d 6e 46 6a 58 77 77 49 49 47 63 6f 78 55 } //1 XIqcjxmvSNORDdOW3SZ5kk8vNzmnFjXwwIIGcoxU
		$a_01_2 = {65 42 71 67 31 71 59 59 32 4d 42 4a 63 34 30 41 69 5a 2e 74 31 6f 51 77 67 57 4e 74 56 61 31 54 34 58 6b 67 4d } //1 eBqg1qYY2MBJc40AiZ.t1oQwgWNtVa1T4XkgM
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}