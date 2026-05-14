
rule Ransom_Win64_Warlock_JKU_MTB{
	meta:
		description = "Ransom:Win64/Warlock.JKU!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 45 43 54 20 4c 4f 43 4b 45 52 } //1 VECT LOCKER
		$a_01_1 = {45 4e 43 52 59 50 54 49 4e 47 } //1 ENCRYPTING
		$a_01_2 = {46 69 6c 65 73 20 45 6e 63 72 79 70 74 65 64 } //1 Files Encrypted
		$a_01_3 = {41 6c 6c 20 66 69 6c 65 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 65 6e 63 72 79 70 74 65 64 } //1 All files successfully encrypted
		$a_01_4 = {45 4e 43 52 59 50 54 49 4f 4e 20 43 4f 4d 50 4c 45 54 45 } //1 ENCRYPTION COMPLETE
		$a_01_5 = {43 68 65 63 6b 20 21 21 21 5f 52 45 41 44 5f 4d 45 } //1 Check !!!_READ_ME
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}