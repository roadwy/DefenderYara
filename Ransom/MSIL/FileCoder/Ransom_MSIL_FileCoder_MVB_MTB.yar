
rule Ransom_MSIL_FileCoder_MVB_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 05 00 "
		
	strings :
		$a_80_0 = {54 69 6e 79 54 72 69 67 67 65 72 2e 65 78 65 } //TinyTrigger.exe  02 00 
		$a_80_1 = {46 69 6c 65 73 20 61 72 65 20 45 6e 63 72 79 70 74 65 64 20 62 79 20 54 69 6e 79 20 54 72 69 67 67 65 72 21 } //Files are Encrypted by Tiny Trigger!  01 00 
		$a_80_2 = {4c 69 76 65 20 6f 72 20 44 69 65 } //Live or Die  01 00 
		$a_00_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_00_4 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_00_5 = {73 65 74 5f 4b 65 79 } //00 00  set_Key
	condition:
		any of ($a_*)
 
}