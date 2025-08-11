
rule Ransom_Win32_IncRansom_YAE_MTB{
	meta:
		description = "Ransom:Win32/IncRansom.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 49 4c 45 20 52 45 43 4f 56 45 52 59 2e 74 78 74 } //1 FILE RECOVERY.txt
		$a_01_1 = {64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 } //10 decrypt one file for free
		$a_01_2 = {52 75 6e 20 71 54 6f 78 } //1 Run qTox
		$a_01_3 = {44 65 63 72 79 70 74 69 6f 6e 20 54 6f 6f 6c 3a } //1 Decryption Tool:
		$a_01_4 = {70 65 72 6d 61 6e 65 6e 74 6c 79 20 64 61 6d 61 67 65 20 74 68 65 6d } //10 permanently damage them
		$a_01_5 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //10 files have been encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=33
 
}