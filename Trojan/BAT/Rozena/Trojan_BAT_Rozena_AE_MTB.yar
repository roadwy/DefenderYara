
rule Trojan_BAT_Rozena_AE_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 00 56 00 20 00 45 00 76 00 61 00 73 00 69 00 6f 00 6e 00 32 00 20 00 2b 00 68 00 65 00 75 00 72 00 69 00 73 00 74 00 69 00 63 00 } //2 AV Evasion2 +heuristic
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //1 GetCurrentProcess
		$a_01_3 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}