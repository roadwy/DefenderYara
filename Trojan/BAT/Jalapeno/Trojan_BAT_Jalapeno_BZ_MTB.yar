
rule Trojan_BAT_Jalapeno_BZ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 72 79 70 74 65 64 46 69 6c 65 2e 65 78 65 } //1 CryptedFile.exe
		$a_81_1 = {53 6f 72 61 61 64 64 2e 52 65 73 6f 75 72 63 65 73 } //1 Soraadd.Resources
		$a_81_2 = {53 6f 72 61 41 64 64 2e 65 78 65 } //1 SoraAdd.exe
		$a_81_3 = {33 36 35 33 37 34 39 33 2d 65 38 35 63 2d 34 64 37 65 2d 39 36 62 63 2d 33 32 63 34 37 32 65 39 36 62 34 63 } //1 36537493-e85c-4d7e-96bc-32c472e96b4c
		$a_81_4 = {37 63 32 33 66 66 39 30 2d 33 33 61 66 2d 31 31 64 33 2d 39 35 64 61 2d 30 30 61 30 32 34 61 38 35 62 35 31 } //1 7c23ff90-33af-11d3-95da-00a024a85b51
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}