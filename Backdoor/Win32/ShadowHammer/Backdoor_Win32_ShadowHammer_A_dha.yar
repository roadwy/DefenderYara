
rule Backdoor_Win32_ShadowHammer_A_dha{
	meta:
		description = "Backdoor:Win32/ShadowHammer.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 68 00 ?? ?? 00 6a 00 ff 15 } //10
		$a_03_1 = {ad ab e2 fc 58 05 ?? ?? 00 00 ff d0 } //10
		$a_00_2 = {41 53 55 53 54 65 4b 20 43 6f 6d 70 75 74 65 72 20 49 6e 63 2e 31 } //10 ASUSTeK Computer Inc.1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}