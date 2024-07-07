
rule Ransom_Win32_Bitpaymer_SA_MSR{
	meta:
		description = "Ransom:Win32/Bitpaymer.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 76 65 6c 6f 70 65 72 41 76 75 6c 6e 65 72 61 62 69 6c 69 74 69 65 73 } //1 DeveloperAvulnerabilities
		$a_01_1 = {73 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 64 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 } //1 scheduledMalware
		$a_01_2 = {61 00 6e 00 64 00 62 00 6c 00 65 00 65 00 64 00 69 00 6e 00 67 00 } //1 andbleeding
		$a_01_3 = {6e 00 79 00 61 00 6e 00 6b 00 65 00 65 00 73 00 } //1 nyankees
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}