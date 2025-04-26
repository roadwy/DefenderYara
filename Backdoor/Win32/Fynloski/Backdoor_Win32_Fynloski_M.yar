
rule Backdoor_Win32_Fynloski_M{
	meta:
		description = "Backdoor:Win32/Fynloski.M,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {23 42 4f 54 23 56 69 73 69 74 55 72 6c } //1 #BOT#VisitUrl
		$a_01_1 = {23 42 4f 54 23 4f 70 65 6e 55 72 6c } //1 #BOT#OpenUrl
		$a_01_2 = {23 42 4f 54 23 53 76 72 55 6e 69 6e 73 74 61 6c 6c } //1 #BOT#SvrUninstall
		$a_01_3 = {23 42 4f 54 23 55 52 4c 44 6f 77 6e 6c 6f 61 64 } //1 #BOT#URLDownload
		$a_01_4 = {4b 49 4c 4c 52 45 4d 4f 54 45 53 48 45 4c 4c } //1 KILLREMOTESHELL
		$a_03_5 = {30 04 32 46 ff 4d ?? 90 13 43 81 e3 ff 00 00 80 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}