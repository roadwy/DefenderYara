
rule Ransom_MSIL_DonutCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/DonutCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 64 00 6f 00 6e 00 75 00 74 00 } //1 .donut
		$a_01_1 = {64 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 } //1 decrypt.txt
		$a_01_2 = {66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 20 00 62 00 79 00 20 00 44 00 4f 00 4e 00 55 00 54 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //3 files have been ENCRYPTED by DONUT Ransomware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}