
rule Ransom_Win64_LockBit_YAC_MTB{
	meta:
		description = "Ransom:Win64/LockBit.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //10 data are stolen and encrypted
		$a_01_1 = {4c 6f 63 6b 42 69 74 20 33 2e 30 20 } //1 LockBit 3.0 
		$a_01_2 = {77 6f 72 6c 64 27 73 20 66 61 73 74 65 73 74 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 world's fastest ransomware
		$a_01_3 = {64 61 74 61 20 77 69 6c 6c 20 62 65 20 70 75 62 6c 69 73 68 65 64 20 6f 6e 20 54 4f 52 20 77 65 62 73 69 74 65 } //1 data will be published on TOR website
		$a_01_4 = {64 6f 20 6e 6f 74 20 70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d } //1 do not pay the ransom
		$a_01_5 = {20 64 65 6c 65 74 65 20 79 6f 75 72 20 64 61 74 61 20 } //1  delete your data 
		$a_01_6 = {64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 } //1 decrypt one file for free
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}