
rule Trojan_Win64_DriftNet_A{
	meta:
		description = "Trojan:Win64/DriftNet.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 70 72 6f 6a 65 63 74 73 5c 6d 6f 64 75 6c 65 73 5c 73 68 65 6c 6c 63 6f 64 65 5c 73 68 65 6c 6c 63 6f 64 65 5f 6d 6f 64 75 6c 65 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 73 68 65 6c 6c 63 6f 64 65 5f 6d 6f 64 75 6c 65 2e 70 64 62 00 } //1
		$a_01_1 = {61 64 73 66 38 31 69 73 61 6b 61 61 6b 30 78 00 } //1 摡晳ㄸ獩歡慡にx
		$a_01_2 = {41 b9 04 00 00 00 41 b8 00 30 00 00 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}