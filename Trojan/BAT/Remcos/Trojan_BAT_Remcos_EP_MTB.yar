
rule Trojan_BAT_Remcos_EP_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {01 25 16 02 28 ?? ?? ?? 06 a2 14 14 14 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 13 0c 11 07 6c 04 6c 5b 13 0d 02 11 0c 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 7d ?? ?? ?? 04 11 0d 0a 2b 25 00 00 11 07 13 06 16 13 0e 2b } //10
		$a_81_1 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //1 ISectionEntry
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}