
rule Ransom_MSIL_Nebula_YBE_MTB{
	meta:
		description = "Ransom:MSIL/Nebula.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 73 20 41 72 65 20 45 6e 63 72 79 70 74 65 64 20 42 79 20 4e 65 62 75 6c 61 } //1 Files Are Encrypted By Nebula
		$a_01_1 = {4b 6e 6f 77 6c 65 64 67 65 20 49 73 20 45 6e 63 72 79 70 74 65 64 } //1 Knowledge Is Encrypted
		$a_01_2 = {59 6f 75 20 48 61 76 65 20 54 6f 20 50 61 79 } //1 You Have To Pay
		$a_01_3 = {50 65 72 6d 61 6e 65 6e 74 20 44 61 74 61 20 4c 6f 73 73 } //1 Permanent Data Loss
		$a_01_4 = {46 69 6c 65 73 20 54 6f 20 4c 6f 63 6b 65 64 20 55 70 } //1 Files To Locked Up
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}