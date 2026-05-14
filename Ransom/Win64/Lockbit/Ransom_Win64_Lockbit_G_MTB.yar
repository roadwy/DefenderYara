
rule Ransom_Win64_Lockbit_G_MTB{
	meta:
		description = "Ransom:Win64/Lockbit.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 Your data are stolen and encrypted
		$a_01_1 = {4c 6f 63 6b 42 69 74 20 35 2e 30 20 74 68 65 20 77 6f 72 6c 64 27 73 20 66 61 73 74 65 73 74 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 LockBit 5.0 the world's fastest ransomware
		$a_01_2 = {2f 2f 74 77 69 74 74 65 72 2e 63 6f 6d 2f 68 61 73 68 74 61 67 2f 6c 6f 63 6b 62 69 74 } //1 //twitter.com/hashtag/lockbit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}