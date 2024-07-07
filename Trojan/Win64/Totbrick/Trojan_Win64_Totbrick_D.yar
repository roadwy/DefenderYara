
rule Trojan_Win64_Totbrick_D{
	meta:
		description = "Trojan:Win64/Totbrick.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 67 72 6f 75 70 00 00 64 69 6e 6a 00 00 00 00 6c 6d 00 00 68 6c 00 00 73 71 00 00 70 72 69 00 } //1
		$a_01_1 = {73 69 6e 6a 00 00 00 00 73 72 76 00 6d 6d 00 00 73 6d 00 00 6e 68 00 } //1
		$a_01_2 = {48 63 c9 48 2b c2 48 c1 f8 05 48 3b c8 73 15 48 c1 e1 05 48 03 ca 48 83 79 18 10 72 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}