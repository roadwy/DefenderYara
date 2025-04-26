
rule Ransom_Win64_Conti_RPJ_MTB{
	meta:
		description = "Ransom:Win64/Conti.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 8b 55 fc 48 63 ca 48 8b 55 f0 48 01 ca 0f b6 00 88 02 83 45 fc 01 8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 84 c0 } //1
		$a_00_1 = {c6 45 b3 56 c6 45 b4 69 c6 45 b5 72 c6 45 b6 74 c6 45 b7 75 c6 45 b8 61 c6 45 b9 6c c6 45 ba 41 c6 45 bb 6c c6 45 bc 6c c6 45 bd 6f c6 45 be 63 } //1
		$a_01_2 = {c6 45 aa 6b c6 45 ab 65 c6 45 ac 72 c6 45 ad 6e c6 45 ae 65 c6 45 af 6c c6 45 b0 33 c6 45 b1 32 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}