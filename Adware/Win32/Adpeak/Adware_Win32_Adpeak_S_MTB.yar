
rule Adware_Win32_Adpeak_S_MTB{
	meta:
		description = "Adware:Win32/Adpeak.S!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 4c 53 49 44 5c 7b 31 30 41 44 32 43 36 31 2d 30 38 39 38 2d 34 33 34 38 2d 38 36 30 30 2d 31 34 41 33 34 32 46 32 32 41 43 33 7d } //1 CLSID\{10AD2C61-0898-4348-8600-14A342F22AC3}
		$a_01_1 = {64 2e 6b 68 62 30 39 77 2e 63 6f 6d 2f 78 75 69 6f 77 } //1 d.khb09w.com/xuiow
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 41 70 70 44 61 74 61 4c 6f 77 5c 53 6f 66 74 77 61 72 65 5c 53 63 6f 72 70 69 6f 6e 53 61 76 65 72 } //1 Software\AppDataLow\Software\ScorpionSaver
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}