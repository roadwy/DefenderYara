
rule Ransom_Win32_DeathRansom_ADT_MTB{
	meta:
		description = "Ransom:Win32/DeathRansom.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {8a c3 c0 e8 07 0f b6 c0 6b c8 1b 8a c3 02 c0 32 c8 32 d9 3a da } //2
		$a_01_1 = {44 45 41 54 48 52 61 6e 73 6f 6d } //1 DEATHRansom
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Your files were encrypted
		$a_01_3 = {59 6f 75 20 68 61 76 65 20 6f 6e 6c 79 20 31 32 20 68 6f 75 72 73 20 74 6f 20 64 65 63 72 79 70 74 20 69 74 } //1 You have only 12 hours to decrypt it
		$a_01_4 = {49 6e 20 63 61 73 65 20 6f 66 20 6e 6f 20 61 6e 73 77 65 72 20 6f 75 72 20 74 65 61 6d 20 77 69 6c 6c 20 64 65 6c 65 74 65 20 79 6f 75 72 20 64 65 63 72 79 70 74 69 6f 6e 20 70 61 73 73 77 6f 72 64 } //1 In case of no answer our team will delete your decryption password
		$a_01_5 = {57 72 69 74 65 20 62 61 63 6b 20 74 6f 20 6f 75 72 20 65 2d 6d 61 69 6c 3a 20 64 65 61 74 68 72 61 6e 73 6f 6d 40 61 69 72 6d 61 69 6c 2e 63 63 } //1 Write back to our e-mail: deathransom@airmail.cc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}