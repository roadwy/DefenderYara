
rule Virus_Win32_Lobaost_A{
	meta:
		description = "Virus:Win32/Lobaost.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 2e 65 78 65 00 ff ff ff ff 05 00 00 00 73 68 61 72 61 00 00 00 ff ff ff ff 0b 00 00 00 6c 6f 61 64 5f 6d 65 2e 65 78 65 } //1
		$a_01_1 = {73 63 20 64 65 6c 65 74 65 20 41 6e 74 69 56 69 72 57 65 62 53 65 72 76 69 63 65 00 73 63 20 64 65 6c 65 74 65 20 41 6e 74 69 56 69 72 53 65 72 76 69 63 65 00 } //1
		$a_01_2 = {68 10 27 00 00 e8 12 5b fe ff e8 05 e6 ff ff e8 98 fc ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}