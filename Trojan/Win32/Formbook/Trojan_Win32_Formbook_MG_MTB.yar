
rule Trojan_Win32_Formbook_MG_MTB{
	meta:
		description = "Trojan:Win32/Formbook.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 6b 63 6f 65 64 63 6c 78 66 6b 63 6b 64 6c } //10 Hkcoedclxfkckdl
		$a_03_1 = {83 c1 01 89 [0-06] 8b [0-06] 3b [0-06] 0f 83 [0-05] 8b 45 ?? 03 [0-06] 8a 08 88 [0-06] 0f b6 [0-40] f7 d2 88 [0-06] 0f b6 } //2
		$a_01_2 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //2 SetClipboardData
		$a_01_3 = {53 6c 65 65 70 } //2 Sleep
		$a_01_4 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //2 GetTempPathA
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=18
 
}