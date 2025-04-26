
rule Trojan_BAT_Razzy_RPZ_MTB{
	meta:
		description = "Trojan:BAT/Razzy.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {7e 05 00 00 04 06 7e 05 00 00 04 06 91 06 61 20 aa 00 00 00 61 d2 9c 06 17 58 0a 06 7e 05 00 00 04 8e 69 fe 04 2d d9 } //1
		$a_01_1 = {44 61 74 61 45 73 74 61 74 65 41 73 73 65 73 73 6d 65 6e 74 2e 73 63 72 69 70 74 2e 70 73 31 } //1 DataEstateAssessment.script.ps1
		$a_01_2 = {45 39 44 34 44 46 32 35 2d 32 32 33 45 2d 34 34 34 46 2d 42 43 37 32 2d 35 34 37 44 30 37 46 36 43 38 37 30 } //1 E9D4DF25-223E-444F-BC72-547D07F6C870
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {43 6f 6e 73 6f 6c 65 53 68 65 6c 6c } //1 ConsoleShell
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}