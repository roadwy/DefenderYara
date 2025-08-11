
rule Ransom_Win64_Babuk_GZZ_MTB{
	meta:
		description = "Ransom:Win64/Babuk.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 83 71 02 6b 66 83 71 04 3f 66 83 71 0a 49 66 83 71 10 0b 66 83 71 12 6b 66 83 71 14 3f 66 83 71 1a 49 66 83 71 20 0b 66 83 71 22 6b 66 83 71 24 3f c6 41 26 00 48 8b c1 } //10
		$a_01_1 = {63 72 69 74 69 63 61 6c 20 70 6f 69 6e 74 73 20 6f 66 20 79 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 72 6f 6d 69 73 65 64 } //1 critical points of your network has been compromised
		$a_01_2 = {61 6c 6c 20 6f 66 20 79 6f 75 72 20 63 6f 6d 70 61 6e 79 27 73 20 63 72 69 74 69 63 61 6c 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 74 72 61 6e 73 66 65 72 72 65 64 20 74 6f 20 6f 75 72 20 73 65 72 76 65 72 73 } //1 all of your company's critical data has been transferred to our servers
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}