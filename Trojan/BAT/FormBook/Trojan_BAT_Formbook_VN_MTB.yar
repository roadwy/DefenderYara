
rule Trojan_BAT_Formbook_VN_MTB{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 72 90 01 03 70 a2 25 17 7e 90 01 03 04 a2 25 18 7e 90 01 03 04 a2 0a 06 28 90 01 03 0a 00 06 73 90 01 03 06 0b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Formbook_VN_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 72 90 01 03 70 a2 0a 28 90 01 03 0a 28 90 01 03 06 28 90 01 03 06 28 90 01 03 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Formbook_VN_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 d2 81 90 01 03 01 00 06 17 58 0a 06 02 8e 69 fe 90 01 01 0c 08 2d 90 09 15 00 02 06 8f 90 01 03 01 25 71 90 01 03 01 7e 90 01 03 04 06 1f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Formbook_VN_MTB_4{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0b 2b 90 01 01 00 02 07 8f 90 01 03 01 25 71 90 01 03 01 06 07 1f 90 01 01 5d 91 61 d2 81 90 01 03 01 00 07 17 58 0b 07 02 8e 69 fe 90 01 01 0d 09 2d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Formbook_VN_MTB_5{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 00 02 72 90 01 03 70 7d 90 01 03 04 02 72 90 01 03 70 7d 90 01 03 04 02 19 8d 90 01 03 01 25 16 02 7b 90 01 03 04 a2 25 17 02 7b 90 01 03 04 a2 7d 90 01 03 04 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Formbook_VN_MTB_6{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 00 7e 90 01 03 04 0a 06 16 7e 90 01 03 04 a2 06 17 7e 90 01 03 04 a2 06 73 90 01 03 06 0b 02 90 00 } //1
		$a_03_1 = {04 0b 07 16 7e 90 01 03 04 a2 07 17 7e 90 01 03 04 a2 06 6f 90 01 03 0a 16 9a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_BAT_Formbook_VN_MTB_7{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 0a 06 16 02 28 90 01 03 06 a2 06 17 02 28 90 01 03 06 a2 06 18 72 90 01 03 70 a2 06 73 90 01 03 06 0b 2b 90 01 01 07 2a 90 00 } //1
		$a_03_1 = {01 0a 19 8d 90 01 03 01 25 16 02 28 90 01 03 06 a2 25 17 02 28 90 01 03 06 a2 25 18 02 28 90 01 03 06 a2 0a 06 73 90 01 03 06 0b 2b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_BAT_Formbook_VN_MTB_8{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_1 = {4d 61 74 68 4c 69 62 72 61 72 79 2e 50 72 6f 70 65 72 74 69 65 73 } //1 MathLibrary.Properties
		$a_81_2 = {53 74 61 72 74 47 61 6d 65 } //1 StartGame
		$a_81_3 = {24 34 38 36 34 37 34 63 66 2d 39 30 33 38 2d 34 31 63 32 2d 38 35 35 65 2d 62 37 61 36 34 39 32 62 35 34 61 65 } //1 $486474cf-9038-41c2-855e-b7a6492b54ae
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_BAT_Formbook_VN_MTB_9{
	meta:
		description = "Trojan:BAT/Formbook.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0c 19 8d 90 01 03 01 80 90 01 03 04 7e 90 01 03 04 16 7e 90 01 03 04 a2 7e 90 01 03 04 17 7e 90 01 03 04 a2 02 07 28 90 01 03 0a 7e 90 01 03 04 28 90 01 03 06 26 06 2a 90 00 } //1
		$a_03_1 = {01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 72 90 01 03 70 a2 73 90 01 03 06 0a 2a 90 09 05 00 19 8d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}