
rule Ransom_MSIL_FileCoder_AYA_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 55 00 69 00 5c 00 75 00 6e 00 6c 00 6f 00 63 00 6b 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 2e 00 6c 00 6e 00 6b 00 } //2 Users\Public\Windows\Ui\unlock your files.lnk
		$a_01_1 = {44 65 6c 65 74 65 53 68 61 64 6f 77 43 6f 70 69 65 73 } //1 DeleteShadowCopies
		$a_00_2 = {61 00 6c 00 65 00 72 00 74 00 6d 00 73 00 67 00 2e 00 7a 00 69 00 70 00 } //1 alertmsg.zip
		$a_00_3 = {65 00 72 00 72 00 6f 00 72 00 20 00 68 00 61 00 20 00 62 00 68 00 61 00 69 00 79 00 61 00 } //1 error ha bhaiya
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}