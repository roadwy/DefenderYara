
rule Ransom_MSIL_Filecoder_SUW_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {4a 61 73 6d 69 6e 5f 45 6e 63 72 79 70 74 65 72 } //2 Jasmin_Encrypter
		$a_01_1 = {24 37 38 63 37 36 39 36 31 2d 38 32 34 39 2d 34 65 66 65 2d 39 64 65 32 2d 62 36 65 66 31 35 61 31 38 37 66 37 } //2 $78c76961-8249-4efe-9de2-b6ef15a187f7
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}