
rule Trojan_BAT_Redline_ASGD_MTB{
	meta:
		description = "Trojan:BAT/Redline.ASGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 07 91 61 d2 } //2
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_3 = {43 72 65 61 74 65 54 68 72 65 61 64 } //1 CreateThread
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}