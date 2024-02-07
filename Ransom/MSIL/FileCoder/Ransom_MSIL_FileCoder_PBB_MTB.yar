
rule Ransom_MSIL_FileCoder_PBB_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.PBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 18 5b 8d 90 01 04 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 90 01 04 1f 10 28 90 01 04 9c 08 18 58 0c 08 06 32 e4 90 00 } //01 00 
		$a_01_1 = {53 65 72 6f 58 65 6e 5c 53 65 72 6f 58 65 6e 5c 6f 62 6a 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 53 65 72 6f 58 65 6e 2e 70 64 62 } //01 00  SeroXen\SeroXen\obj\x64\Release\SeroXen.pdb
		$a_01_2 = {41 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  Ace.exe
	condition:
		any of ($a_*)
 
}