
rule Ransom_Win32_BlackBasta_PA_MTB{
	meta:
		description = "Ransom:Win32/BlackBasta.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 62 00 61 00 73 00 74 00 61 00 } //1 .basta
		$a_01_1 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //1 readme.txt
		$a_01_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin.exe delete shadows /all /quiet
		$a_01_3 = {59 6f 75 72 20 64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 Your data are stolen and encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}