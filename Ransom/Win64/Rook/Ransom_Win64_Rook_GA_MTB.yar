
rule Ransom_Win64_Rook_GA_MTB{
	meta:
		description = "Ransom:Win64/Rook.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 "
		
	strings :
		$a_01_0 = {44 61 74 61 20 61 74 20 74 68 65 20 6d 61 69 6e 20 63 72 69 74 69 63 61 6c 20 70 6f 69 6e 74 73 20 6f 66 20 79 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 72 6f 6d 69 73 65 64 2c 20 61 6e 64 20 61 6c 6c 20 6f 66 20 79 6f 75 72 20 63 6f 6d 70 61 6e 79 27 73 20 63 72 69 74 69 63 61 6c 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 74 72 61 6e 73 66 65 72 72 65 64 20 74 6f 20 6f 75 72 20 73 65 72 76 65 72 73 2e } //1 Data at the main critical points of your network has been compromised, and all of your company's critical data has been transferred to our servers.
		$a_01_1 = {47 6f 6f 64 20 6e 65 77 73 3a } //1 Good news:
		$a_01_2 = {57 65 20 63 61 6e 20 72 65 73 74 6f 72 65 20 31 30 30 25 20 6f 66 20 79 6f 75 72 20 73 79 73 74 65 6d 73 20 61 6e 64 20 64 61 74 61 2e } //1 We can restore 100% of your systems and data.
		$a_01_3 = {49 66 20 77 65 20 61 67 72 65 65 2c 20 6f 6e 6c 79 20 79 6f 75 20 61 6e 64 20 6f 75 72 20 74 65 61 6d 20 77 69 6c 6c 20 6b 6e 6f 77 20 61 62 6f 75 74 20 74 68 69 73 20 62 72 65 61 63 68 2e } //1 If we agree, only you and our team will know about this breach.
		$a_01_4 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_01_5 = {44 65 63 72 79 70 74 69 6f 6e 20 61 6e 64 20 72 65 73 74 6f 72 61 74 69 6f 6e 20 6f 66 20 61 6c 6c 20 79 6f 75 72 20 73 79 73 74 65 6d 73 20 61 6e 64 20 64 61 74 61 20 77 69 74 68 69 6e 20 32 34 20 68 6f 75 72 73 20 77 69 74 68 20 61 20 31 30 30 25 20 67 75 61 72 61 6e 74 65 65 3b } //1 Decryption and restoration of all your systems and data within 24 hours with a 100% guarantee;
		$a_01_6 = {4e 6f 74 68 69 6e 67 20 70 65 72 73 6f 6e 61 6c 2c 20 6a 75 73 74 20 62 75 73 69 6e 65 73 73 } //1 Nothing personal, just business
		$a_00_7 = {72 00 65 00 61 00 64 00 5f 00 6d 00 65 00 5f 00 74 00 6f 00 5f 00 61 00 63 00 63 00 65 00 73 00 73 00 2e 00 74 00 78 00 74 00 } //1 read_me_to_access.txt
		$a_00_8 = {6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 log.txt
		$a_00_9 = {6b 00 65 00 79 00 2e 00 70 00 75 00 62 00 } //1 key.pub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=9
 
}