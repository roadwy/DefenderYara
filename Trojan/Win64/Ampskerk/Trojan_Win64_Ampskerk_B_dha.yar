
rule Trojan_Win64_Ampskerk_B_dha{
	meta:
		description = "Trojan:Win64/Ampskerk.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {66 83 3a 26 75 1b 66 83 38 4b 75 15 66 83 78 0e 73 75 0e 66 83 78 1e 4b } //5
		$a_01_1 = {48 6f 6f 6b 44 43 2e 64 6c 6c 00 69 00 75 00 } //3
		$a_01_2 = {48 6f 6f 6b 44 43 2e 64 6c 6c 00 69 69 00 75 75 00 } //3
		$a_01_3 = {73 61 6d 73 72 76 2e 64 6c 6c } //1 samsrv.dll
		$a_01_4 = {63 72 79 70 74 64 6c 6c 2e 64 6c 6c } //1 cryptdll.dll
		$a_01_5 = {53 61 6d 49 52 65 74 72 69 65 76 65 50 72 69 6d 61 72 79 43 72 65 64 65 6e 74 69 61 6c 73 } //1 SamIRetrievePrimaryCredentials
		$a_01_6 = {53 61 6d 49 52 65 74 72 69 65 76 65 4d 75 6c 74 69 70 6c 65 50 72 69 6d 61 72 79 43 72 65 64 65 6e 74 69 61 6c 73 } //1 SamIRetrieveMultiplePrimaryCredentials
		$a_01_7 = {43 44 4c 6f 63 61 74 65 43 53 79 73 74 65 6d } //1 CDLocateCSystem
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}