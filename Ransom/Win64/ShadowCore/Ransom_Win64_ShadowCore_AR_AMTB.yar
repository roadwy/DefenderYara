
rule Ransom_Win64_ShadowCore_AR_AMTB{
	meta:
		description = "Ransom:Win64/ShadowCore.AR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin delete shadows /all /quiet  1
		$a_80_1 = {53 48 41 44 4f 57 20 43 4f 52 45 20 52 41 4e 53 4f 4d 57 41 52 45 } //SHADOW CORE RANSOMWARE  1
		$a_80_2 = {41 66 74 65 72 20 64 65 61 64 6c 69 6e 65 3a 20 50 45 52 4d 41 4e 45 4e 54 20 44 41 54 41 20 4c 4f 53 53 } //After deadline: PERMANENT DATA LOSS  1
		$a_80_3 = {45 6d 61 69 6c 20 74 72 61 6e 73 61 63 74 69 6f 6e 20 49 44 20 74 6f 3a 20 73 68 61 64 6f 77 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //Email transaction ID to: shadow@tutanota.com  1
		$a_80_4 = {5c 21 21 21 53 48 41 44 4f 57 5f 52 45 41 44 5f 4d 45 21 21 21 2e 74 78 74 } //\!!!SHADOW_READ_ME!!!.txt  1
		$a_80_5 = {2e 53 48 41 44 4f 57 4c 4f 43 4b 45 44 } //.SHADOWLOCKED  1
		$a_80_6 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 53 48 41 44 4f 57 20 43 4f 52 45 20 72 61 6e 73 6f 6d 77 61 72 65 } //Your files have been encrypted by SHADOW CORE ransomware  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}