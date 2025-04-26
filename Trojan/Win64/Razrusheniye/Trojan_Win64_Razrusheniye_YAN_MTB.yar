
rule Trojan_Win64_Razrusheniye_YAN_MTB{
	meta:
		description = "Trojan:Win64/Razrusheniye.YAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 69 63 74 69 6d 20 6f 66 20 74 68 65 20 72 61 7a 72 75 73 68 65 6e 69 79 65 20 72 61 6e 73 6f 6d 77 61 72 65 21 } //10 victim of the razrusheniye ransomware!
		$a_01_1 = {57 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 74 68 65 73 65 20 66 69 6c 65 73 } //1 We can decrypt these files
		$a_01_2 = {68 6f 75 72 73 20 69 66 20 79 6f 75 20 70 61 79 } //1 hours if you pay
		$a_01_3 = {77 69 6c 6c 20 73 65 6e 74 20 79 6f 75 20 61 20 64 65 63 72 79 70 74 6f 72 } //1 will sent you a decryptor
		$a_01_4 = {73 79 73 74 65 6d 20 77 69 6c 6c 20 62 65 20 6a 75 73 74 20 61 73 20 6e 65 77 } //1 system will be just as new
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}