
rule Trojan_BAT_KillMBR_NM_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 8d 22 00 00 01 0a 72 ?? 00 00 70 20 ?? 00 00 10 19 7e ?? 00 00 0a 19 16 7e ?? 00 00 0a 28 ?? 00 00 06 0b } //3
		$a_01_1 = {24 66 34 35 34 30 31 63 38 2d 30 33 34 65 2d 34 61 35 63 2d 39 63 30 36 2d 31 35 64 64 38 30 39 33 33 30 31 64 } //1 $f45401c8-034e-4a5c-9c06-15dd8093301d
		$a_01_2 = {2f 00 6b 00 20 00 72 00 65 00 67 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 68 00 6b 00 6c 00 6d 00 20 00 2f 00 66 00 } //1 /k reg delete hklm /f
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_KillMBR_NM_MTB_2{
	meta:
		description = "Trojan:BAT/KillMBR.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {22 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 22 00 20 00 69 00 73 00 20 00 76 00 65 00 72 00 79 00 20 00 69 00 6e 00 73 00 65 00 63 00 75 00 72 00 } //2 "encryption" is very insecur
		$a_01_1 = {53 00 61 00 76 00 65 00 20 00 74 00 68 00 65 00 20 00 6b 00 65 00 79 00 20 00 79 00 6f 00 75 00 20 00 73 00 65 00 74 00 2c 00 20 00 6f 00 74 00 68 00 65 00 72 00 77 00 69 00 73 00 65 00 2c 00 20 00 77 00 68 00 65 00 6e 00 20 00 79 00 6f 00 75 00 20 00 77 00 61 00 6e 00 74 00 20 00 74 00 6f 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 2c 00 20 00 69 00 74 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 76 00 65 00 72 00 79 00 20 00 64 00 69 00 66 00 66 00 69 00 63 00 75 00 6c 00 74 00 20 00 6f 00 72 00 20 00 69 00 6d 00 70 00 6f 00 73 00 73 00 69 00 62 00 6c 00 65 00 } //2 Save the key you set, otherwise, when you want to decrypt your files, it will be very difficult or impossible
		$a_01_2 = {61 00 20 00 74 00 6f 00 6f 00 6c 00 6b 00 69 00 74 00 20 00 74 00 68 00 61 00 74 00 20 00 6c 00 6f 00 6f 00 6b 00 73 00 20 00 6c 00 69 00 6b 00 65 00 20 00 61 00 20 00 76 00 69 00 72 00 75 00 73 00 20 00 62 00 75 00 74 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 } //2 a toolkit that looks like a virus but is not
		$a_01_3 = {72 78 5f 64 65 66 65 6e 64 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 rx_defender.Properties.Resources
		$a_01_4 = {43 00 53 00 68 00 61 00 72 00 70 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 72 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 6c 00 6f 00 61 00 64 00 65 00 64 00 21 00 } //1 CSharp Executer has been loaded!
		$a_01_5 = {24 37 38 63 35 62 66 63 63 2d 36 39 31 37 2d 34 31 61 35 2d 61 33 37 61 2d 62 34 62 30 35 33 61 37 65 39 64 63 } //1 $78c5bfcc-6917-41a5-a37a-b4b053a7e9dc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}