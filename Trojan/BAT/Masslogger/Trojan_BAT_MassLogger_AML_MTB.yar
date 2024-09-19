
rule Trojan_BAT_MassLogger_AML_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 67 67 53 65 63 75 72 69 74 79 43 68 65 63 6b 65 72 2e 46 72 6f 67 67 41 62 6f 75 74 2e 72 65 73 6f 75 72 63 65 73 } //1 FroggSecurityChecker.FroggAbout.resources
		$a_01_1 = {31 33 66 33 38 65 61 61 2d 34 34 37 65 2d 34 30 35 39 2d 38 64 62 62 2d 61 62 32 31 35 64 36 61 30 65 61 61 } //1 13f38eaa-447e-4059-8dbb-ab215d6a0eaa
		$a_01_2 = {70 00 6f 00 77 00 65 00 72 00 65 00 64 00 20 00 62 00 79 00 20 00 61 00 64 00 6d 00 69 00 6e 00 40 00 66 00 72 00 6f 00 67 00 67 00 2e 00 66 00 72 00 } //2 powered by admin@frogg.fr
		$a_01_3 = {46 00 72 00 6f 00 67 00 67 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 43 00 68 00 65 00 63 00 6b 00 65 00 72 00 } //2 Frogg Security Checker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}