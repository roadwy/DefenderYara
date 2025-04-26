
rule Trojan_Win64_IcedID_MAC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 31 31 70 77 2e 64 6c 6c } //1 e11pw.dll
		$a_01_1 = {73 61 62 68 6a 61 73 6a 61 6b } //1 sabhjasjak
		$a_01_2 = {44 4b 70 6e 57 79 32 75 } //1 DKpnWy2u
		$a_01_3 = {52 4b 78 4b 54 52 70 31 73 63 33 } //1 RKxKTRp1sc3
		$a_01_4 = {56 39 4c 53 57 6c 37 77 70 51 } //1 V9LSWl7wpQ
		$a_01_5 = {6e 36 65 49 63 6d 68 49 53 } //1 n6eIcmhIS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}