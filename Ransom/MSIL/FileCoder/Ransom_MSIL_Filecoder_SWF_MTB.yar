
rule Ransom_MSIL_Filecoder_SWF_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 66 65 38 33 31 65 31 37 2d 34 39 32 62 2d 34 61 66 32 2d 62 36 38 36 2d 37 39 35 63 36 66 62 63 64 66 39 32 } //2 $fe831e17-492b-4af2-b686-795c6fbcdf92
		$a_01_1 = {6d 61 6a 6f 72 64 6f 6d 5c 63 6c 69 65 6e 74 5c 6d 61 6a 6f 72 64 6f 6d 5c 6d 61 6a 6f 72 64 6f 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 6d 61 6a 6f 72 64 6f 6d 2e 70 64 62 } //2 majordom\client\majordom\majordom\obj\Debug\majordom.pdb
		$a_01_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}