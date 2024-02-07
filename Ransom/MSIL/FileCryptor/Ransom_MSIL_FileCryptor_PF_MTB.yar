
rule Ransom_MSIL_FileCryptor_PF_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 69 74 44 65 63 6f 64 65 72 } //01 00  BitDecoder
		$a_01_1 = {44 65 63 6f 64 65 57 69 74 68 4d 61 74 63 68 42 79 74 65 } //01 00  DecodeWithMatchByte
		$a_01_2 = {24 62 65 32 37 35 30 39 61 2d 63 31 31 62 2d 34 33 31 34 2d 62 30 32 63 2d 36 33 35 35 64 35 32 61 63 65 38 61 } //01 00  $be27509a-c11b-4314-b02c-6355d52ace8a
		$a_80_3 = {43 52 59 50 54 2e 65 78 65 } //CRYPT.exe  00 00 
	condition:
		any of ($a_*)
 
}