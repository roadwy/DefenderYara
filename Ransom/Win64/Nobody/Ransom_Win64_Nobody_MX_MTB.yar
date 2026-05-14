
rule Ransom_Win64_Nobody_MX_MTB{
	meta:
		description = "Ransom:Win64/Nobody.MX!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 6e 6f 62 6f 64 79 63 72 79 } //5 .nobodycry
		$a_01_1 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 6e 6f 62 6f 64 79 2e 65 78 65 } //1 ProgramData\nobody.exe
		$a_01_2 = {4e 6f 62 6f 64 79 63 72 79 70 74 } //1 Nobodycrypt
		$a_01_3 = {52 75 73 6f 63 72 79 70 74 } //1 Rusocrypt
		$a_01_4 = {4c 6f 63 61 6c 5c 6e 6f 62 6f 64 79 72 6d 72 66 } //1 Local\nobodyrmrf
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}