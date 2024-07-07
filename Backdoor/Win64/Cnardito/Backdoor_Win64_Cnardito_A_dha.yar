
rule Backdoor_Win64_Cnardito_A_dha{
	meta:
		description = "Backdoor:Win64/Cnardito.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 70 74 32 0f 85 } //2
		$a_00_1 = {74 69 72 61 6e 69 64 64 6f } //2 tiraniddo
		$a_00_2 = {77 65 62 5f 61 75 74 68 2e 64 6c 6c } //1 web_auth.dll
		$a_00_3 = {43 48 74 74 70 4d 6f 64 75 6c 65 3a 3a } //1 CHttpModule::
		$a_00_4 = {25 30 32 64 2f 25 30 32 64 2f 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 } //1 %02d/%02d/%02d %02d:%02d:%02d
		$a_00_5 = {46 61 69 6c 3a 20 25 75 } //1 Fail: %u
		$a_00_6 = {00 52 65 67 69 73 74 65 72 4d 6f 64 75 6c 65 00 } //1 刀来獩整䵲摯汵e
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}