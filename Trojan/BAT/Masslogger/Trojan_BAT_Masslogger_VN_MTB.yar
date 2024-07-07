
rule Trojan_BAT_Masslogger_VN_MTB{
	meta:
		description = "Trojan:BAT/Masslogger.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 72 90 01 03 70 a2 73 90 01 03 06 0a 02 28 90 01 03 06 00 2a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Masslogger_VN_MTB_2{
	meta:
		description = "Trojan:BAT/Masslogger.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {70 0c 19 8d 90 01 03 01 25 16 06 a2 25 17 07 a2 25 18 08 a2 73 90 01 03 06 0d 2a 90 09 10 00 7e 90 01 03 04 0a 7e 90 01 03 04 0b 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Masslogger_VN_MTB_3{
	meta:
		description = "Trojan:BAT/Masslogger.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 9c 90 09 1e 00 fe 90 01 02 00 fe 90 01 02 00 fe 90 01 02 00 fe 90 01 02 00 91 fe 90 01 02 00 61 fe 90 01 02 00 fe 90 01 02 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Masslogger_VN_MTB_4{
	meta:
		description = "Trojan:BAT/Masslogger.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {04 0b 19 8d 90 01 03 01 25 16 06 a2 25 17 07 a2 25 18 20 90 01 04 28 90 01 03 06 a2 73 90 01 03 06 26 2a 90 09 0a 00 7e 90 01 03 04 0a 7e 90 00 } //1
		$a_03_1 = {0b 14 0c 19 8d 90 01 03 01 25 16 06 a2 25 17 07 a2 25 18 72 90 01 03 70 a2 73 90 01 03 06 0d 2a 90 09 0b 00 7e 90 01 03 04 0a 7e 90 01 03 04 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Trojan_BAT_Masslogger_VN_MTB_5{
	meta:
		description = "Trojan:BAT/Masslogger.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {55 52 4c 3d 66 69 6c 65 3a 2f 2f 7a 7a 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 URL=file://zzSOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_03_1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 90 02 1e 5c 00 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00 90 00 } //1
		$a_03_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 90 02 1e 5c 52 65 67 41 73 6d 2e 65 78 65 90 00 } //1
		$a_81_3 = {50 61 73 73 77 6f 72 64 48 61 73 68 } //1 PasswordHash
		$a_81_4 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 } //1 get_StartupPath
		$a_81_5 = {54 41 53 4b 4b 49 4c 6b 69 6c 6c 6c } //1 TASKKILkilll
	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}