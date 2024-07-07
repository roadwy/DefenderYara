
rule Trojan_Win32_Emotet_PDE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 84 34 90 01 04 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8d 4c 24 90 01 01 45 0f b6 94 14 90 01 04 30 55 90 00 } //1
		$a_81_1 = {75 69 4f 74 79 70 41 49 53 30 4b 54 51 66 61 35 70 4b 6a 35 41 4c 62 67 61 4b 41 61 4d 54 48 69 35 5a 68 70 39 52 4c 4c 4b 39 6a } //1 uiOtypAIS0KTQfa5pKj5ALbgaKAaMTHi5Zhp9RLLK9j
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}