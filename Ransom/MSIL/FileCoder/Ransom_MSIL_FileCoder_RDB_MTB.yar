
rule Ransom_MSIL_FileCoder_RDB_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 68 6f 73 74 48 61 63 6b 65 72 } //1 GhostHacker
		$a_01_1 = {4e 6f 43 72 79 } //1 NoCry
		$a_01_2 = {35 30 63 34 39 64 65 39 2d 39 31 34 61 2d 34 32 65 38 2d 61 39 66 36 2d 32 38 35 66 37 63 61 38 63 37 31 65 } //1 50c49de9-914a-42e8-a9f6-285f7ca8c71e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}