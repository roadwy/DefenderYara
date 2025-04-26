
rule Trojan_BAT_Ainslot_ADT_MTB{
	meta:
		description = "Trojan:BAT/Ainslot.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 05 00 00 "
		
	strings :
		$a_02_0 = {08 11 05 02 11 05 91 06 61 09 11 04 91 61 b4 9c 11 04 03 6f ?? ?? ?? 0a 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06 } //10
		$a_80_1 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //get_ExecutablePath  5
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  5
		$a_80_3 = {66 47 70 75 7a 6a 35 64 70 51 47 70 35 69 67 5a 30 63 36 4a 48 79 38 6b 6e 53 64 72 68 71 35 4c 57 49 63 77 43 4a 41 53 54 6a 73 } //fGpuzj5dpQGp5igZ0c6JHy8knSdrhq5LWIcwCJASTjs  4
		$a_80_4 = {4a 67 74 47 2f 6c 52 77 53 7a 67 56 59 6e 57 59 56 37 4b 35 62 79 35 57 4c 53 7a 32 43 30 37 64 4b 46 49 45 2f 50 6d 63 34 48 49 } //JgtG/lRwSzgVYnWYV7K5by5WLSz2C07dKFIE/Pmc4HI  4
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4) >=28
 
}