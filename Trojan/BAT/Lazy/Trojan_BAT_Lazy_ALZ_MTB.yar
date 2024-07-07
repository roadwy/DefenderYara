
rule Trojan_BAT_Lazy_ALZ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0b 72 90 01 01 01 00 70 0c 06 28 90 01 01 00 00 0a 16 fe 01 0d 09 2c 09 00 06 28 90 01 01 00 00 0a 26 00 73 90 01 01 00 00 0a 08 07 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Lazy_ALZ_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 03 1f 10 28 90 01 01 00 00 2b 1f 20 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0c 20 00 00 00 00 38 58 00 00 00 00 38 64 01 00 00 00 73 02 01 00 0a 25 11 04 28 90 01 01 03 00 06 00 25 17 28 90 01 01 03 00 06 00 25 18 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Lazy_ALZ_MTB_3{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 06 07 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 2d 0d 06 07 28 90 01 01 00 00 0a 08 28 90 01 01 00 00 0a de 14 26 72 90 01 01 01 00 70 02 28 90 00 } //1
		$a_01_1 = {0a 0c 08 28 06 00 00 0a 02 6f 07 00 00 0a 6f 08 00 00 0a 08 06 6f 09 00 00 0a 08 08 6f 0a 00 00 0a 08 6f 0b 00 00 0a 6f 0c 00 00 0a 0d 07 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Lazy_ALZ_MTB_4{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 2b 28 09 6f 90 01 01 00 00 0a 74 90 01 01 00 00 01 13 04 00 11 04 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 14 fe 01 13 05 11 05 2c 04 00 17 0a 00 00 09 6f 90 00 } //1
		$a_03_1 = {11 07 17 6f 90 01 01 00 00 0a 00 11 07 17 6f 90 01 01 00 00 0a 00 11 07 16 6f 90 01 01 00 00 0a 00 11 07 17 6f 90 01 01 00 00 0a 00 73 19 00 00 0a 13 08 11 08 11 07 6f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Lazy_ALZ_MTB_5{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 71 00 06 19 11 04 5a 6f 90 01 03 0a 13 05 11 05 1f 39 fe 02 13 07 11 07 2c 0d 11 05 1f 41 59 1f 0a 58 d1 13 05 2b 08 11 05 1f 30 59 d1 13 05 06 19 11 04 5a 17 58 6f 90 01 03 0a 13 06 11 06 1f 39 fe 02 13 08 11 08 2c 0d 11 06 1f 41 59 1f 0a 58 d1 13 06 2b 08 11 06 1f 30 59 d1 13 06 08 11 04 1f 10 11 05 5a 11 06 58 d2 9c 00 11 04 17 58 13 04 11 04 07 fe 04 13 09 11 09 2d 84 90 00 } //2
		$a_01_1 = {50 00 65 00 6c 00 61 00 79 00 6f 00 53 00 4e 00 6f 00 6e 00 6f 00 67 00 72 00 61 00 6d 00 73 00 } //1 PelayoSNonograms
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Lazy_ALZ_MTB_6{
	meta:
		description = "Trojan:BAT/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 1d 08 09 9a 03 28 90 01 01 00 00 06 13 04 11 04 28 90 01 01 00 00 0a 2d 05 11 04 0b de 2b 09 17 58 0d 09 08 8e 69 90 00 } //2
		$a_01_1 = {6f 62 6a 5c 52 65 6c 65 61 73 65 5c 57 61 67 65 72 73 73 69 5f 55 49 20 4c 61 75 6e 63 68 65 72 2e 70 64 62 } //1 obj\Release\Wagerssi_UI Launcher.pdb
		$a_01_2 = {48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 57 00 4f 00 57 00 36 00 34 00 33 00 32 00 4e 00 6f 00 64 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 57 00 6f 00 72 00 6c 00 64 00 20 00 6f 00 66 00 20 00 57 00 61 00 72 00 63 00 72 00 61 00 66 00 74 00 } //1 HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\World of Warcraft
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}