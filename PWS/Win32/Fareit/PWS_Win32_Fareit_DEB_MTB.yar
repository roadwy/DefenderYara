
rule PWS_Win32_Fareit_DEB_MTB{
	meta:
		description = "PWS:Win32/Fareit.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {53 56 4f 56 4c 44 49 4f 58 49 44 55 44 53 45 4e 44 45 4c 53 45 4e 53 } //1 SVOVLDIOXIDUDSENDELSENS
		$a_81_1 = {46 6c 75 67 74 73 6b 79 64 6e 69 6e 67 73 62 61 6e 65 6e 35 } //1 Flugtskydningsbanen5
		$a_01_2 = {41 00 67 00 65 00 72 00 68 00 6e 00 73 00 6a 00 61 00 67 00 74 00 65 00 6e 00 32 00 } //1 Agerhnsjagten2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}