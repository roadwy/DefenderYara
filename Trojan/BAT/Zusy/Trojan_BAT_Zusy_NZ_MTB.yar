
rule Trojan_BAT_Zusy_NZ_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 68 00 00 0a 02 6f ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 06 6f ?? 00 00 0a 28 23 00 00 06 } //5
		$a_01_1 = {4d 65 6c 6f 6e 53 70 6f 6f 66 65 72 5f 62 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 MelonSpoofer_b2.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Zusy_NZ_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 28 06 00 00 06 75 ?? ?? ?? 1b 28 ?? ?? ?? 0a 13 04 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff dd ?? ?? ?? ff 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff } //5
		$a_01_1 = {4d 6b 77 69 6d 73 63 78 76 61 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Mkwimscxva.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Zusy_NZ_MTB_3{
	meta:
		description = "Trojan:BAT/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 1b 00 00 01 25 16 72 01 00 00 70 a2 25 17 72 41 00 00 70 a2 25 18 72 7d 00 00 70 a2 13 04 00 11 04 13 0a 16 } //3
		$a_01_1 = {28 26 00 00 0a 7e 07 00 00 04 6f 27 00 00 0a 0a 28 26 00 00 0a 7e 06 00 00 04 6f 27 00 00 0a 0b 02 28 28 00 00 0a 0c 16 13 04 } //2
		$a_01_2 = {50 00 69 00 61 00 6e 00 6f 00 5f 00 49 00 6e 00 5b 00 73 00 74 00 61 00 2f 00 6c 00 65 00 72 00 36 00 34 00 62 00 69 00 74 00 40 00 67 00 6d 00 61 00 69 00 6c 00 23 00 } //1 Piano_In[sta/ler64bit@gmail#
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}
rule Trojan_BAT_Zusy_NZ_MTB_4{
	meta:
		description = "Trojan:BAT/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 0a 72 01 00 00 70 06 72 45 00 00 70 28 17 00 00 0a 0b 73 18 00 00 0a 25 72 49 00 00 70 6f ?? 00 00 0a 00 25 72 67 00 00 70 07 72 7d 00 00 70 28 17 00 00 0a 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 16 6f ?? 00 00 0a 00 25 17 } //3
		$a_03_1 = {20 10 27 00 00 28 ?? 00 00 0a 00 28 ?? 00 00 0a 02 7b 02 00 00 04 6f 2e 00 00 0a 0a 72 33 01 00 70 28 ?? 00 00 0a 0b 07 } //2
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 34 37 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 WindowsFormsApp47.Properties.Resources.resources
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}