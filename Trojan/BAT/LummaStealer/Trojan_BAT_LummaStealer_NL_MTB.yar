
rule Trojan_BAT_LummaStealer_NL_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f c5 07 00 0a 26 02 28 ?? 07 00 0a 0a } //2
		$a_03_1 = {28 c7 07 00 0a 06 16 06 8e 69 6f ?? 07 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_BAT_LummaStealer_NL_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 06 00 00 01 14 14 14 28 44 00 00 0a 28 52 00 00 0a 02 } //3
		$a_03_1 = {7b 66 00 00 04 14 72 ?? 01 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 37 00 00 0a } //3
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_BAT_LummaStealer_NL_MTB_3{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 7e 65 03 00 04 28 ?? ?? 00 06 80 66 03 00 04 28 ?? ?? 00 06 28 a9 13 00 06 28 ?? ?? 00 06 61 28 ?? ?? 00 06 33 11 28 ?? ?? 00 06 80 66 03 00 04 } //5
		$a_01_1 = {4c 6f 61 64 65 72 56 31 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 LoaderV1.Form1.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_LummaStealer_NL_MTB_4{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 28 9e 00 00 0a 39 ?? 00 00 00 7e ?? 00 00 04 74 2f 00 00 01 2a 07 17 58 0b 07 7e 3e 00 00 04 8e 69 3f d2 ff ff ff } //3
		$a_03_1 = {02 6f 9a 00 00 0a 6f ?? 00 00 0a 25 7e ?? 00 00 04 74 2f 00 00 01 6f 9a 00 00 0a 6f 9b 00 00 0a } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_BAT_LummaStealer_NL_MTB_5{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 13 16 11 16 20 ?? ?? ?? 80 2e 1d 11 16 20 ?? ?? ?? 7f 2e 14 08 11 05 07 91 11 06 07 91 58 58 0c 08 20 ?? ?? ?? 00 5d 0c 11 05 07 91 13 0f 11 05 07 11 05 08 91 9c 11 05 08 11 0f 9c 07 17 58 0b 07 20 00 01 00 00 32 b7 } //5
		$a_01_1 = {6b 6a 63 62 6b 6a 69 77 } //1 kjcbkjiw
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_LummaStealer_NL_MTB_6{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 61 74 65 79 6b 6f 5f 63 72 79 70 74 65 64 } //2 Kateyko_crypted
		$a_01_1 = {24 32 61 32 38 31 32 37 39 2d 65 31 61 35 2d 34 62 30 61 2d 62 32 65 66 2d 31 39 32 64 65 39 35 64 33 38 63 64 } //2 $2a281279-e1a5-4b0a-b2ef-192de95d38cd
		$a_01_2 = {4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 20 62 72 6f 77 73 65 72 20 66 6f 72 20 61 6c 6c } //2 Mozilla Firefox browser for all
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_BAT_LummaStealer_NL_MTB_7{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 8d 76 00 00 01 13 14 11 09 28 ?? ?? ?? 0a 16 11 14 16 1a 28 ?? ?? ?? 0a 11 0a 28 36 } //5
		$a_01_1 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 6d 00 5f 00 63 00 61 00 74 00 65 00 67 00 6f 00 72 00 69 00 65 00 73 00 5f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 73 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //1 programm_categories_products_update.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}