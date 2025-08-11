
rule Ransom_MSIL_Emmyware_SK_MTB{
	meta:
		description = "Ransom:MSIL/Emmyware.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {54 41 53 4b 4b 49 4c 4c 20 2f 46 20 2f 49 4d 20 45 58 50 4c 4f 52 45 52 2e 45 58 45 } //1 TASKKILL /F /IM EXPLORER.EXE
		$a_81_1 = {4f 6e 63 65 20 79 6f 75 20 72 75 6e 20 74 68 69 73 2c 20 79 6f 75 27 72 65 20 66 75 63 6b 65 64 21 } //1 Once you run this, you're fucked!
		$a_81_2 = {54 72 6f 6a 61 6e 2e 52 61 6e 73 6f 6d 2e 45 6d 6d 79 77 61 72 65 } //1 Trojan.Ransom.Emmyware
		$a_81_3 = {45 6d 6d 79 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Emmyware.Properties.Resources
		$a_81_4 = {64 63 36 71 6d 6f 6b 2d 37 65 37 30 35 34 64 64 2d 64 37 63 66 2d 34 31 35 61 2d 38 63 35 65 2d 39 33 38 62 31 62 39 39 39 65 34 36 } //1 dc6qmok-7e7054dd-d7cf-415a-8c5e-938b1b999e46
		$a_81_5 = {57 68 61 74 48 61 70 70 65 6e 4c 61 62 65 6c 2e 54 65 78 74 } //1 WhatHappenLabel.Text
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}