
rule Trojan_AndroidOS_Piom_A{
	meta:
		description = "Trojan:AndroidOS/Piom.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 70 70 2e 6a 73 6f 6e } //01 00  app.json
		$a_01_1 = {73 74 61 72 74 2e 70 6e 67 } //01 00  start.png
		$a_01_2 = {48 75 61 6e 79 69 6e 41 63 74 69 76 69 74 79 } //00 00  HuanyinActivity
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Piom_A_2{
	meta:
		description = "Trojan:AndroidOS/Piom.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {49 6e 6a 65 63 74 69 6f 6e 20 69 73 20 73 75 63 63 65 73 73 66 75 6c } //02 00  Injection is successful
		$a_00_1 = {66 67 64 66 76 63 76 2e 6f 72 67 } //02 00  fgdfvcv.org
		$a_00_2 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 62 6f 74 2f 43 6f 6d 6d 61 6e 64 4c 69 73 74 65 6e 65 72 } //00 00  Lcom/example/bot/CommandListener
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Piom_A_3{
	meta:
		description = "Trojan:AndroidOS/Piom.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 37 7a 48 6c 4d 53 4e 5a 6d 48 45 67 31 42 6c 63 6d 31 70 63 33 4e 70 62 32 35 6d 59 63 53 44 59 57 58 45 6a 51 3d 3d } //01 00  w7zHlMSNZmHEg1Blcm1pc3Npb25mYcSDYWXEjQ==
		$a_01_1 = {5a 4d 65 57 78 49 6c 6d 59 63 53 44 5a 32 56 30 55 47 46 30 61 47 5a 68 78 49 50 46 71 38 65 63 78 49 6b } //00 00  ZMeWxIlmYcSDZ2V0UGF0aGZhxIPFq8ecxIk
	condition:
		any of ($a_*)
 
}