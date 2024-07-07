
rule Trojan_Win32_Emotet_DSQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8a 03 83 c4 08 8a 54 14 14 32 c2 88 03 90 09 05 00 b9 90 00 } //1
		$a_81_1 = {4a 41 34 72 59 69 78 66 4b 62 43 72 59 4c 73 62 35 54 31 57 68 4a 41 63 33 72 77 50 77 6b 50 4c 35 61 6b } //1 JA4rYixfKbCrYLsb5T1WhJAc3rwPwkPL5ak
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}