
rule Ransom_MSIL_HonorCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/HonorCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 68 00 6f 00 6e 00 6f 00 72 00 } //1 .honor
		$a_01_1 = {48 00 6f 00 6e 00 6f 00 72 00 27 00 73 00 20 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 } //1 Honor's Malware
		$a_01_2 = {73 00 65 00 63 00 72 00 65 00 74 00 41 00 45 00 53 00 2e 00 74 00 78 00 74 00 } //1 secretAES.txt
		$a_01_3 = {5c 68 6f 6e 6f 72 27 73 20 6d 61 6c 77 61 72 65 2e 70 64 62 } //1 \honor's malware.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}