
rule Trojan_BAT_Jalapeno_MCF_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {11 09 11 0a 11 07 11 0a 91 11 08 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 07 8e 69 fe 04 13 13 11 13 2d de } //10
		$a_01_1 = {52 75 6e 74 69 6d 65 42 72 6f 6b 65 72 } //1 RuntimeBroker
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}