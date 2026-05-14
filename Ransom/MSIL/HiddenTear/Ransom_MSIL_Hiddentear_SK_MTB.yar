
rule Ransom_MSIL_Hiddentear_SK_MTB{
	meta:
		description = "Ransom:MSIL/Hiddentear.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {68 65 6c 73 2e 72 65 61 64 6d 65 2e 74 78 74 } //1 hels.readme.txt
		$a_81_1 = {42 4c 41 43 4b 2d 48 45 4f 4c 41 53 } //1 BLACK-HEOLAS
		$a_81_2 = {59 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 6c 6f 63 6b 65 64 20 62 79 20 65 6e 63 72 79 70 74 69 6f 6e } //1 Your important files are locked by encryption
		$a_81_3 = {42 6c 61 63 6b 48 65 6f 6c 61 73 53 75 70 70 6f 72 74 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //1 BlackHeolasSupport@onionmail.org
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}