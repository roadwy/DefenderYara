
rule Trojan_Win64_Quasarrat_RR_MTB{
	meta:
		description = "Trojan:Win64/Quasarrat.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_00_0 = {43 00 68 00 61 00 69 00 6e 00 69 00 6e 00 67 00 4d 00 6f 00 64 00 65 00 43 00 42 00 43 00 } //1 ChainingModeCBC
		$a_00_1 = {43 00 68 00 61 00 69 00 6e 00 69 00 6e 00 67 00 4d 00 6f 00 64 00 65 00 } //1 ChainingMode
		$a_01_2 = {41 57 41 56 41 55 41 54 56 57 55 53 48 } //1 AWAVAUATVWUSH
		$a_01_3 = {55 41 57 41 56 41 55 41 54 56 57 53 50 48 } //1 UAWAVAUATVWSPH
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_6 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
		$a_01_7 = {62 63 72 79 70 74 2e 64 6c 6c } //1 bcrypt.dll
		$a_01_8 = {42 43 72 79 70 74 44 65 73 74 72 6f 79 4b 65 79 } //1 BCryptDestroyKey
		$a_01_9 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_10 = {48 83 c4 20 c7 06 00 00 00 00 48 83 ec 20 4c 89 f9 4c 89 ea 41 b8 20 00 00 00 49 89 f1 41 ff d4 48 83 c4 20 85 c0 0f 84 } //5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*5) >=15
 
}