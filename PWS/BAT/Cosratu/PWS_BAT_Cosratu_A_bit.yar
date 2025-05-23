
rule PWS_BAT_Cosratu_A_bit{
	meta:
		description = "PWS:BAT/Cosratu.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {06 02 07 6f 09 00 00 0a 03 07 03 6f 0a 00 00 0a 5d 6f 09 00 00 0a 61 d1 6f 0b 00 00 0a 26 07 17 58 0b } //1
		$a_01_1 = {63 6f 73 74 75 72 61 2e 64 65 63 72 79 70 74 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 costura.decrypt.dll.compressed
		$a_01_2 = {00 49 56 69 63 74 69 6d 43 61 6c 6c 62 61 63 6b 00 } //1
		$a_01_3 = {00 53 65 6e 64 55 72 6c 41 6e 64 45 78 65 63 75 74 65 00 } //1
		$a_01_4 = {00 42 69 74 63 6f 69 6e 57 61 6c 6c 65 74 00 } //1
		$a_01_5 = {00 43 72 65 61 74 65 43 6f 6d 70 61 74 69 62 6c 65 42 69 74 6d 61 70 00 46 72 6f 6d 48 62 69 74 6d 61 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}