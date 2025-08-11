
rule Trojan_BAT_KatzStealer_DA_MTB{
	meta:
		description = "Trojan:BAT/KatzStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {45 78 65 63 75 74 61 72 4d 65 74 6f 64 6f 56 41 49 } //1 ExecutarMetodoVAI
		$a_81_1 = {56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 44 65 74 65 63 74 6f 72 } //1 VirtualMachineDetector
		$a_81_2 = {57 6f 77 36 34 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 5f 41 50 49 } //1 Wow64SetThreadContext_API
		$a_81_3 = {6e 6f 6d 65 64 6f 61 72 71 75 69 76 6f } //1 nomedoarquivo
		$a_81_4 = {70 61 79 6c 6f 61 64 42 75 66 66 65 72 } //1 payloadBuffer
		$a_81_5 = {63 61 6d 69 6e 68 6f 76 62 73 } //1 caminhovbs
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}