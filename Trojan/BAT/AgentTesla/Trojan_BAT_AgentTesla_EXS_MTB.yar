
rule Trojan_BAT_AgentTesla_EXS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 65 30 33 35 30 62 37 62 2d 35 33 39 32 2d 34 37 35 39 2d 38 32 33 31 2d 32 38 30 61 62 31 65 64 35 65 64 34 } //10 $e0350b7b-5392-4759-8231-280ab1ed5ed4
		$a_01_1 = {24 65 63 36 66 35 35 65 31 2d 31 64 35 34 2d 34 35 63 35 2d 62 66 64 63 2d 61 34 39 66 61 33 63 66 37 66 37 64 } //10 $ec6f55e1-1d54-45c5-bfdc-a49fa3cf7f7d
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}
rule Trojan_BAT_AgentTesla_EXS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 73 00 43 00 65 00 77 00 45 00 41 00 41 00 41 00 51 00 67 00 67 00 51 00 49 00 41 00 41 00 43 00 43 00 75 00 41 00 67 00 41 00 41 00 4b 00 41 00 49 00 41 00 41 00 43 00 73 00 4b 00 45 00 51 00 59 00 } //1 CsCewEAAAQggQIAACCuAgAAKAIAACsKEQY
		$a_01_1 = {6b 00 41 00 41 00 41 00 41 00 57 00 77 00 41 00 41 00 41 00 4e 00 41 00 56 00 41 00 41 00 41 00 47 00 4a 00 68 00 45 00 46 00 48 00 7a 00 53 00 52 00 49 00 50 00 41 00 41 00 41 00 41 00 42 00 2b 00 46 00 } //1 kAAAAWwAAANAVAAAGJhEFHzSRIPAAAAB+F
		$a_01_2 = {00 47 65 74 4d 65 74 68 6f 64 00 } //1
		$a_01_3 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 } //1 䘀潲䉭獡㙥匴牴湩g
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}