
rule Trojan_BAT_RedLine_MF_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 11 04 08 11 04 9a 1f 10 28 90 01 03 0a 9c 11 04 17 d6 13 04 00 11 04 20 90 01 03 00 fe 04 13 06 11 06 2d db 09 13 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_RedLine_MF_MTB_2{
	meta:
		description = "Trojan:BAT/RedLine.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0c 06 08 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 02 16 03 8e 69 6f 90 01 01 00 00 0a 0d 09 13 04 2b 00 11 04 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_RedLine_MF_MTB_3{
	meta:
		description = "Trojan:BAT/RedLine.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 02 16 02 8e 69 28 90 01 03 06 2a 73 53 00 00 0a 38 62 ff ff ff 0a 38 61 ff ff ff 0b 38 67 ff ff ff 73 54 00 00 0a 38 67 ff ff ff 28 90 01 03 06 38 6c ff ff ff 03 38 6b ff ff ff 28 90 01 03 06 38 66 ff ff ff 28 90 01 03 06 38 61 ff ff ff 0c 38 60 ff ff ff 90 00 } //01 00 
		$a_01_1 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00 
		$a_01_4 = {47 65 74 42 79 74 65 73 } //01 00 
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00 
		$a_01_7 = {66 64 73 66 66 66 66 64 66 66 73 64 66 } //00 00 
	condition:
		any of ($a_*)
 
}