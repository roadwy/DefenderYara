
rule Ransom_Linux_0APTLOCKER_B_MSR{
	meta:
		description = "Ransom:Linux/0APTLOCKER.B!MSR,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {30 41 50 54 20 4c 4f 43 4b 45 52 } //1 0APT LOCKER
		$a_01_1 = {73 72 63 2f 62 69 6e 2f 65 6e 63 72 79 70 74 2e 72 73 } //1 src/bin/encrypt.rs
		$a_01_2 = {30 61 70 74 52 45 41 44 4d 45 30 61 70 74 2e 74 78 74 } //1 0aptREADME0apt.txt
		$a_01_3 = {65 6e 63 72 79 70 74 5f 77 69 74 68 5f 62 61 63 6b 65 6e 64 } //1 encrypt_with_backend
		$a_03_4 = {74 74 70 3a 2f 2f 6f 61 70 74 [0-55] 2e 6f 6e 69 6f 6e 2f 6c 6f 67 69 6e 2e 70 68 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}