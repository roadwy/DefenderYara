
rule Trojan_BAT_XWorm_AYC_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 11 06 07 02 07 6f ?? 00 00 0a 03 61 d1 9d 07 17 58 0b 07 02 6f ?? 00 00 0a 32 e6 06 73 ?? 00 00 0a 2a } //7
		$a_01_1 = {44 45 45 44 53 48 47 46 48 43 2e 52 65 73 6f 75 72 63 65 73 } //3 DEEDSHGFHC.Resources
		$a_00_2 = {61 00 61 00 61 00 2e 00 65 00 78 00 65 00 } //1 aaa.exe
		$a_00_3 = {46 00 69 00 6c 00 65 00 20 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 65 00 78 00 65 00 } //1 File Google.exe
	condition:
		((#a_03_0  & 1)*7+(#a_01_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}