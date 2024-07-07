
rule Ransom_MacOS_LockBit_A{
	meta:
		description = "Ransom:MacOS/LockBit.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {dd 00 94 e1 03 00 aa e0 03 80 52 02 00 80 d2 03 00 80 52 90 01 02 00 94 1f 04 00 31 90 00 } //1
		$a_00_1 = {0a 0d 40 92 aa 6a 6a 38 ab 02 08 8b 6c 41 40 39 8a 01 0a 4a 6a 41 00 39 08 05 00 91 1f 01 09 eb 01 ff ff 54 } //1
		$a_00_2 = {72 65 73 74 6f 72 65 2d 6d 79 2d 66 69 6c 65 73 2e 74 78 74 } //1 restore-my-files.txt
		$a_00_3 = {73 6f 64 69 75 6d 5f 63 72 69 74 5f 65 6e 74 65 72 } //1 sodium_crit_enter
		$a_00_4 = {62 6c 61 6b 65 32 62 2d 72 65 66 2e 63 } //1 blake2b-ref.c
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}