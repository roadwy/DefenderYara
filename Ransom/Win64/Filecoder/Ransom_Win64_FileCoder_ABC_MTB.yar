
rule Ransom_Win64_FileCoder_ABC_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.ABC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 03 c8 48 8b c1 0f b6 40 01 88 04 24 0f b6 04 24 83 e8 62 6b c0 d9 99 b9 7f 00 00 00 f7 f9 8b c2 83 c0 7f 99 b9 7f 00 00 00 f7 f9 8b c2 48 8b 4c 24 08 48 8b 54 24 20 48 03 d1 48 8b ca 88 41 01 } //00 00 
	condition:
		any of ($a_*)
 
}