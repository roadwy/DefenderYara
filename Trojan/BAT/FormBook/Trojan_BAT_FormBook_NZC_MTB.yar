
rule Trojan_BAT_FormBook_NZC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {00 03 04 05 5d 05 58 05 5d 91 0a 2b 00 06 2a } //2
		$a_01_1 = {00 03 04 03 8e 69 5d 03 8e 69 58 03 8e 69 5d 91 0a 2b 00 06 2a } //2
		$a_01_2 = {00 04 05 5d 05 58 05 5d 0a 03 06 91 0b } //2
		$a_81_3 = {47 65 74 47 56 61 6c 75 65 } //1 GetGValue
		$a_81_4 = {78 6f 72 42 79 74 65 } //1 xorByte
		$a_81_5 = {47 65 74 58 6f 72 42 79 74 65 } //1 GetXorByte
		$a_81_6 = {43 61 6c 63 75 6c 61 74 65 4b 69 } //1 CalculateKi
		$a_81_7 = {43 61 6c 63 75 6c 61 74 65 49 6e 74 65 72 6d 65 64 69 61 74 65 33 } //1 CalculateIntermediate3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=11
 
}