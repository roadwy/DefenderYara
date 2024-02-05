
rule Trojan_Win32_Camec_H{
	meta:
		description = "Trojan:Win32/Camec.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 3b f3 0f 8c 90 01 01 00 00 00 66 6b ff 40 66 8b 45 dc 0f 80 90 01 01 01 00 00 66 03 fe 0f 80 90 01 01 01 00 00 66 05 06 00 0f 80 90 01 01 01 00 00 66 3d 08 00 90 00 } //01 00 
		$a_03_1 = {51 ff d6 6a 90 01 01 8d 90 01 03 ff ff 90 01 01 ff d6 6a 90 01 01 8d 90 01 03 ff ff 90 01 01 ff d6 6a 90 01 01 8d 90 01 03 ff ff 90 01 01 ff d6 6a 90 00 } //01 00 
		$a_00_2 = {46 49 4f 62 6a 65 63 74 57 69 74 68 53 69 74 65 5f 53 65 74 53 69 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}