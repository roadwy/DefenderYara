
rule Trojan_AndroidOS_Qicsomos_A{
	meta:
		description = "Trojan:AndroidOS/Qicsomos.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 6a 65 63 74 76 6f 6f 64 6f 6f 2f 73 69 6d 70 6c 65 63 61 72 72 69 65 72 69 71 64 65 74 65 63 74 6f 72 } //1 projectvoodoo/simplecarrieriqdetector
		$a_01_1 = {53 55 53 50 49 43 49 4f 55 53 5f 43 4c 41 53 53 45 53 } //1 SUSPICIOUS_CLASSES
		$a_01_2 = {63 64 6d 61 5f 73 68 61 64 6f 77 } //1 cdma_shadow
		$a_01_3 = {73 75 62 6d 69 74 41 4c 33 34 } //1 submitAL34
		$a_01_4 = {41 67 65 6e 74 53 65 72 76 69 63 65 5f 4a } //1 AgentService_J
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}