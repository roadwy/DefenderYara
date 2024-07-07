
rule Trojan_BAT_Polazert_RS_MTB{
	meta:
		description = "Trojan:BAT/Polazert.RS!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {7a 00 6b 00 61 00 62 00 73 00 72 00 } //4 zkabsr
		$a_01_1 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 } //1 GetEnvironmentVariable
		$a_01_2 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
		$a_01_3 = {47 65 74 45 6e 75 6d 65 72 61 74 6f 72 } //1 GetEnumerator
		$a_01_4 = {4b 65 79 56 61 6c 75 65 50 61 69 72 } //1 KeyValuePair
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {67 65 74 5f 4d 61 63 68 69 6e 65 4e 61 6d 65 } //1 get_MachineName
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}