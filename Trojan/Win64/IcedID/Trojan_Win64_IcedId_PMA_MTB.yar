
rule Trojan_Win64_IcedId_PMA_MTB{
	meta:
		description = "Trojan:Win64/IcedId.PMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 67 61 77 62 68 6a 6b 64 68 61 62 73 68 64 6a 61 73 } //1 ygawbhjkdhabshdjas
		$a_01_1 = {4f 6e 49 61 69 68 45 41 56 35 } //1 OnIaihEAV5
		$a_01_2 = {5a 51 51 61 6f 66 } //1 ZQQaof
		$a_01_3 = {62 53 6b 4b 59 70 63 70 } //1 bSkKYpcp
		$a_01_4 = {66 5a 47 35 71 52 65 53 58 34 } //1 fZG5qReSX4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}