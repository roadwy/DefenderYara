
rule Ransom_Win64_Radar_YAB_MTB{
	meta:
		description = "Ransom:Win64/Radar.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 ba 0a 0a 52 41 44 41 52 0a 48 89 10 48 ba 0a 59 6f 75 72 20 6e 65 } //1
		$a_01_1 = {64 61 74 61 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 data were encrypted
		$a_01_2 = {70 75 72 63 68 61 73 65 20 52 41 44 41 52 20 44 65 63 72 79 70 74 6f 72 20 66 72 6f 6d 20 75 73 } //1 purchase RADAR Decryptor from us
		$a_01_3 = {72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 rename encrypted files
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}