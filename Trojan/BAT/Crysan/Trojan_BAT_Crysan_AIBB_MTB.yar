
rule Trojan_BAT_Crysan_AIBB_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AIBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_3 = {51 00 7a 00 70 00 63 00 55 00 48 00 4a 00 76 00 5a 00 33 00 4a 00 68 00 62 00 55 00 52 00 68 00 64 00 47 00 46 00 63 00 54 00 57 00 6c 00 6a 00 63 00 6d 00 39 00 7a 00 62 00 32 00 5a 00 30 00 58 00 45 00 56 00 6b 00 5a 00 32 00 56 00 56 00 63 00 47 00 52 00 68 00 64 00 47 00 55 00 75 00 5a 00 47 00 78 00 73 00 } //10 QzpcUHJvZ3JhbURhdGFcTWljcm9zb2Z0XEVkZ2VVcGRhdGUuZGxs
		$a_01_4 = {63 00 32 00 6c 00 6f 00 62 00 33 00 4e 00 30 00 } //5 c2lob3N0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*5) >=18
 
}