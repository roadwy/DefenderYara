
rule Trojan_BAT_RedLineStealer_MAV_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.MAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {70 72 6b 50 51 51 64 69 43 73 63 } //1 prkPQQdiCsc
		$a_81_1 = {76 61 4f 70 65 6c 6a 43 53 4f 78 73 4a 57 4e 6f 68 46 51 6d } //1 vaOpeljCSOxsJWNohFQm
		$a_01_2 = {43 72 79 70 74 6f 43 6f 6e 76 65 72 74 } //1 CryptoConvert
		$a_01_3 = {4b 69 6c 6c } //1 Kill
		$a_01_4 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_5 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_6 = {57 00 6f 00 77 00 36 00 34 00 47 00 65 00 74 00 54 00 68 00 72 00 65 00 61 00 64 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 } //1 Wow64GetThreadContext
		$a_01_7 = {52 00 65 00 61 00 64 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 ReadProcessMemory
		$a_01_8 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 45 00 78 00 } //1 VirtualAllocEx
		$a_01_9 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 WriteProcessMemory
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}