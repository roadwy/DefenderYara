
rule Ransom_MSIL_HiddenTears_SUR_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTears.SUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 4f 52 43 45 5f 42 53 4f 44 40 50 61 79 6c 6f 61 64 73 } //2 FORCE_BSOD@Payloads
		$a_01_1 = {4d 42 52 5f 4f 76 65 72 77 72 69 74 65 40 50 61 79 6c 6f 61 64 73 } //2 MBR_Overwrite@Payloads
		$a_01_2 = {53 63 72 65 65 6e 5f 47 6c 69 74 63 68 69 6e 67 40 50 61 79 6c 6f 61 64 73 } //2 Screen_Glitching@Payloads
		$a_01_3 = {47 65 74 46 69 6c 65 73 41 6e 64 45 6e 63 72 79 70 74 } //1 GetFilesAndEncrypt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}