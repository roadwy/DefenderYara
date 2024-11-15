
rule Ransom_MSIL_FileCoder_AYD_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 61 6e 53 6f 6d 57 61 72 65 2e 65 78 65 } //2 RanSomWare.exe
		$a_01_1 = {52 61 6e 53 6f 6d 57 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 } //2 RanSomWare.Properties
		$a_01_2 = {24 35 33 33 65 36 36 66 63 2d 38 62 35 63 2d 34 64 36 37 2d 38 63 62 63 2d 31 63 61 63 38 35 32 31 64 65 33 62 } //1 $533e66fc-8b5c-4d67-8cbc-1cac8521de3b
		$a_01_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}