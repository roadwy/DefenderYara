
rule Ransom_Win32_RagnarLocker_C_dha{
	meta:
		description = "Ransom:Win32/RagnarLocker.C!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 72 72 6f 72 20 65 6e 63 72 79 70 74 3a 20 25 73 } //1 error encrypt: %s
		$a_01_1 = {49 66 20 79 6f 75 20 61 72 65 20 72 65 61 64 69 6e 67 20 74 68 69 73 20 6d 65 73 73 61 67 65 2c 20 69 74 20 6d 65 61 6e 73 20 74 68 61 74 3a 20 } //1 If you are reading this message, it means that: 
		$a_01_2 = {44 20 41 20 52 20 4b 20 20 20 20 41 20 4e 20 47 20 45 20 4c 20 53 20 20 20 54 20 45 20 41 20 4d 20 20 21 } //1 D A R K    A N G E L S   T E A M  !
		$a_01_3 = {43 6f 6f 70 65 72 61 74 69 6e 67 20 77 69 74 68 20 74 68 65 20 46 42 49 2c 20 43 49 53 41 20 61 6e 64 20 73 6f 20 6f 6e } //1 Cooperating with the FBI, CISA and so on
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}