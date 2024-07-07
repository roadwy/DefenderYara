
rule TrojanSpy_Win32_Banker_AOR{
	meta:
		description = "TrojanSpy:Win32/Banker.AOR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 "
		
	strings :
		$a_01_0 = {63 6f 75 6e 74 64 6f 6e 77 54 4d 50 5f 43 41 58 41 4c 59 54 52 55 53 50 } //1 countdonwTMP_CAXALYTRUSP
		$a_01_1 = {63 6f 75 6e 74 64 6f 6e 77 54 4d 50 5f 53 49 43 52 59 4e 41 53 54 } //1 countdonwTMP_SICRYNAST
		$a_01_2 = {63 6f 75 6e 74 64 6f 6e 77 54 4d 50 5f 53 49 43 4f 4f 4e 41 53 58 } //1 countdonwTMP_SICOONASX
		$a_01_3 = {63 6f 75 6e 74 64 6f 6e 77 54 4d 50 5f 53 41 4e 54 59 4e 59 } //1 countdonwTMP_SANTYNY
		$a_01_4 = {63 6f 75 6e 74 64 6f 6e 77 54 4d 50 5f 42 52 41 53 43 4f 53 4b } //1 countdonwTMP_BRASCOSK
		$a_01_5 = {48 53 42 43 41 4c 4b 52 59 54 69 6d 65 72 } //1 HSBCALKRYTimer
		$a_01_6 = {53 49 43 4f 4f 4e 41 53 54 69 6d 65 72 } //1 SICOONASTimer
		$a_01_7 = {42 52 41 53 43 4f 53 4b 54 69 6d 65 72 } //1 BRASCOSKTimer
		$a_01_8 = {69 6d 67 53 61 6e 74 61 } //1 imgSanta
		$a_01_9 = {69 6d 67 42 61 6e 72 69 } //1 imgBanri
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=6
 
}