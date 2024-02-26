
rule Ransom_MSIL_FileCoder_MVT_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {46 65 6e 72 69 6b 77 61 72 65 } //01 00  Fenrikware
		$a_80_1 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //files have been encrypted  01 00 
		$a_80_2 = {53 68 61 64 6f 77 43 6f 70 79 } //ShadowCopy  01 00 
		$a_00_3 = {46 69 6c 75 6d 45 6e 63 72 79 70 74 6f } //00 00  FilumEncrypto
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_FileCoder_MVT_MTB_2{
	meta:
		description = "Ransom:MSIL/FileCoder.MVT!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {78 61 71 69 70 61 78 6f 77 71 2e 65 78 65 } //01 00  xaqipaxowq.exe
		$a_01_1 = {5a 61 64 69 6c 6f 6b } //01 00  Zadilok
		$a_01_2 = {42 69 63 6c 61 76 65 6b } //01 00  Biclavek
		$a_01_3 = {43 6f 70 79 72 69 67 68 74 20 45 64 61 72 69 6d 65 6e 75 6d } //00 00  Copyright Edarimenum
	condition:
		any of ($a_*)
 
}