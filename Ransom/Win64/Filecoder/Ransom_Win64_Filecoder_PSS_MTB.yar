
rule Ransom_Win64_Filecoder_PSS_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c5 fe 6f 0a c5 fe 6f 52 20 c5 fe 6f 5a 40 c5 fe 6f 62 60 c5 fd 7f 09 c5 fd 7f 51 20 c5 fd 7f 59 40 c5 fd 7f 61 60 c5 fe 6f 8a 80 00 00 00 c5 fe 6f 92 a0 00 00 00 c5 fe 6f 9a c0 00 00 00 c5 fe 6f a2 e0 00 00 00 c5 fd 7f 89 80 00 00 00 c5 fd 7f 91 a0 00 00 00 c5 fd 7f 99 c0 00 00 00 c5 fd 7f a1 e0 00 00 00 48 81 c1 00 01 00 00 48 81 c2 00 01 00 00 49 81 e8 00 01 00 00 49 81 f8 00 01 00 00 0f 83 78 ff ff ff } //01 00 
		$a_01_1 = {c4 a1 7e 6f 4c 0a c0 c4 a1 7e 7f 4c 09 c0 c4 a1 7e 7f 6c 01 e0 c5 fe 7f 00 c5 f8 77 c3 } //01 00 
		$a_01_2 = {66 75 6e 63 5f 62 61 6e 65 20 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}