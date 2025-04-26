
rule Trojan_BAT_Dopdekaf_A_MTB{
	meta:
		description = "Trojan:BAT/Dopdekaf.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {01 57 95 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 21 00 00 00 05 00 00 00 2f 01 00 00 1e } //4
		$a_01_1 = {48 61 6e 64 6c 65 50 72 6f 63 65 73 73 43 6f 72 72 75 70 74 65 64 53 74 61 74 65 45 78 63 65 70 74 69 6f 6e 73 41 74 74 72 69 62 75 74 65 } //1 HandleProcessCorruptedStateExceptionsAttribute
		$a_01_2 = {46 69 6c 65 41 63 63 65 73 73 } //1 FileAccess
		$a_01_3 = {46 69 6c 65 53 68 61 72 65 } //1 FileShare
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}