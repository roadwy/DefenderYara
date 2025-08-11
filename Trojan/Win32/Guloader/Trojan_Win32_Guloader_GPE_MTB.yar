
rule Trojan_Win32_Guloader_GPE_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {75 6e 69 6f 6e 65 72 6e 65 } //1 unionerne
		$a_81_1 = {6f 76 65 72 67 61 61 65 74 20 63 79 74 6f 73 74 72 6f 6d 61 2e 65 78 65 } //1 overgaaet cytostroma.exe
		$a_81_2 = {67 73 72 6d 65 72 52 69 63 68 73 6d 65 72 } //1 gsrmerRichsmer
		$a_81_3 = {64 73 7c 6d 65 72 73 6d 64 72 } //1 ds|mersmdr
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}