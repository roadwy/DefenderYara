
rule Ransom_MSIL_Charity_YAA_MTB{
	meta:
		description = "Ransom:MSIL/Charity.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 00 43 00 48 00 41 00 52 00 49 00 54 00 59 00 } //1 .CHARITY
		$a_01_1 = {52 00 41 00 4e 00 53 00 4f 00 4d 00 5f 00 4e 00 4f 00 54 00 45 00 2e 00 74 00 78 00 74 00 } //1 RANSOM_NOTE.txt
		$a_01_2 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 72 00 65 00 6d 00 6f 00 76 00 65 00 64 00 } //1 encrypted and removed
		$a_01_3 = {61 00 70 00 70 00 72 00 65 00 63 00 69 00 61 00 74 00 65 00 20 00 79 00 6f 00 75 00 72 00 20 00 64 00 6f 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 } //1 appreciate your donation
		$a_01_4 = {72 65 63 6f 76 65 72 20 6d 79 20 66 69 6c 65 73 } //1 recover my files
		$a_01_5 = {52 61 6e 73 6f 6d 5c 43 68 61 72 69 74 79 2d 6d 61 73 74 65 72 } //1 Ransom\Charity-master
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}