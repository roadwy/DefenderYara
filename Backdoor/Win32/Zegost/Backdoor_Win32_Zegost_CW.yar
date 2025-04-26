
rule Backdoor_Win32_Zegost_CW{
	meta:
		description = "Backdoor:Win32/Zegost.CW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 11 80 c3 ?? 88 1c 11 8b ?? ?? ?? 8a 1c 11 80 f3 ?? 88 1c 11 } //2
		$a_03_1 = {8a 0c 30 80 f1 ?? 88 0c 30 40 3b c7 72 f2 } //2
		$a_01_2 = {0d 0a 3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}