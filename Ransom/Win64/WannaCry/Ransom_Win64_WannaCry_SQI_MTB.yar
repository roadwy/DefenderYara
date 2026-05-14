
rule Ransom_Win64_WannaCry_SQI_MTB{
	meta:
		description = "Ransom:Win64/WannaCry.SQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {40 57 61 6e 61 44 65 63 72 79 70 74 6f 72 40 2e 65 78 65 } //2 @WanaDecryptor@.exe
		$a_81_1 = {40 50 6c 65 61 73 65 5f 52 65 61 64 5f 4d 65 40 2e 74 78 74 } //1 @Please_Read_Me@.txt
		$a_81_2 = {57 61 6e 6e 61 43 72 79 5f 41 45 53 5f 4b 45 59 } //1 WannaCry_AES_KEY
		$a_81_3 = {2e 57 4e 43 52 59 } //1 .WNCRY
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}