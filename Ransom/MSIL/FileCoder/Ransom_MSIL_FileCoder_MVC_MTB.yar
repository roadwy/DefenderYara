
rule Ransom_MSIL_FileCoder_MVC_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.MVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {54 61 65 4d 69 6e 56 69 72 75 73 2e 65 78 65 } //01 00  TaeMinVirus.exe
		$a_80_1 = {49 20 67 6f 74 20 69 6e 74 6f 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //I got into your computer  01 00 
		$a_80_2 = {54 68 65 72 65 27 73 20 6e 6f 20 65 78 69 74 } //There's no exit  00 00 
	condition:
		any of ($a_*)
 
}