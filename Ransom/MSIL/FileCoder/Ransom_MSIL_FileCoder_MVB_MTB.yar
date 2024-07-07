
rule Ransom_MSIL_FileCoder_MVB_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_80_0 = {54 69 6e 79 54 72 69 67 67 65 72 2e 65 78 65 } //TinyTrigger.exe  5
		$a_80_1 = {46 69 6c 65 73 20 61 72 65 20 45 6e 63 72 79 70 74 65 64 20 62 79 20 54 69 6e 79 20 54 72 69 67 67 65 72 21 } //Files are Encrypted by Tiny Trigger!  2
		$a_80_2 = {4c 69 76 65 20 6f 72 20 44 69 65 } //Live or Die  1
		$a_00_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_00_4 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_00_5 = {73 65 74 5f 4b 65 79 } //1 set_Key
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=7
 
}