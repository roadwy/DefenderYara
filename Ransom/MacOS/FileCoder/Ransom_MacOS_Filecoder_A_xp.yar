
rule Ransom_MacOS_Filecoder_A_xp{
	meta:
		description = "Ransom:MacOS/Filecoder.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {52 45 41 44 4d 45 2e 74 78 74 } //1 README.txt
		$a_00_1 = {7b 7d 2e 63 72 79 70 74 } //1 {}.crypt
		$a_01_2 = {32 30 31 30 30 32 31 33 30 30 30 30 } //1 201002130000
		$a_00_3 = {20 72 69 68 6f 66 6f 6a 40 7a 61 69 6e 6d 61 78 2e 6e 65 74 } //1  rihofoj@zainmax.net
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}