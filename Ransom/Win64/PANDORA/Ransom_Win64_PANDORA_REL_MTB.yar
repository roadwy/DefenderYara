
rule Ransom_Win64_PANDORA_REL_MTB{
	meta:
		description = "Ransom:Win64/PANDORA.REL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 ff cf 48 85 db 75 2b 4d 8b c6 48 8b d5 49 8b cd e8 8a f1 ff ff ba 01 00 00 00 48 8d 45 0f 48 2b d5 80 00 01 75 0c 48 ff c8 48 8d 0c 02 48 85 c9 7f ef 42 0f b6 0c 33 41 0f b6 04 37 32 c8 88 0e 48 ff c6 48 ff c3 83 e3 0f 48 85 ff } //9c ff 
		$a_01_1 = {75 73 61 67 65 3a 20 72 73 61 5f 76 65 72 69 66 79 5f 70 73 73 20 3c 6b 65 79 5f 66 69 6c 65 3e 20 3c 66 69 6c 65 6e 61 6d 65 3e } //00 00 
	condition:
		any of ($a_*)
 
}