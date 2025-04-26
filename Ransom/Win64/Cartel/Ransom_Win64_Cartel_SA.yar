
rule Ransom_Win64_Cartel_SA{
	meta:
		description = "Ransom:Win64/Cartel.SA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 61 74 68 62 75 69 67 65 } //rathbuige  1
		$a_80_1 = {73 65 72 76 69 63 65 6d 61 69 6e } //servicemain  1
		$a_80_2 = {73 76 63 68 6f 73 74 70 75 73 68 73 65 72 76 69 63 65 67 6c 6f 62 61 6c 73 } //svchostpushserviceglobals  1
		$a_80_3 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin.exe delete shadows /all /quiet  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}