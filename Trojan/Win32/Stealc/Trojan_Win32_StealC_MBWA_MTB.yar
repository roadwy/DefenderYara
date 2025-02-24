
rule Trojan_Win32_StealC_MBWA_MTB{
	meta:
		description = "Trojan:Win32/StealC.MBWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_81_0 = {47 65 68 65 62 69 6e 75 77 65 6a 75 77 20 73 61 78 65 70 61 62 61 6c 69 6c 69 77 75 77 47 46 61 70 61 6a 75 62 } //1 Gehebinuwejuw saxepabaliliwuwGFapajub
		$a_81_1 = {54 6f 62 75 6d 6f 74 75 70 69 6b 6f 74 61 20 73 61 63 65 73 69 66 61 68 6f 67 20 74 75 6d 69 68 75 62 6f 76 6f 68 65 6a } //1 Tobumotupikota sacesifahog tumihubovohej
		$a_81_2 = {4a 69 62 75 20 7a 65 63 20 70 75 67 6f 6c 65 2f 4b 65 6d 6f 20 79 61 63 75 63 69 79 6f 66 69 20 70 6f 62 69 64 65 79 75 73 61 6b 61 73 6f } //1 Jibu zec pugole/Kemo yacuciyofi pobideyusakaso
		$a_81_3 = {57 6f 68 6f 76 6f 66 61 77 61 6d 75 6a 20 6a 75 72 61 6a 61 6b 6f 74 69 72 69 68 20 6a 75 74 65 76 65 79 6f 6d 75 6c 69 68 61 63 20 6b 65 66 69 74 69 78 65 6b 6f 7a 20 6d 6f 7a 65 72 65 63 6f 6e 61 20 67 65 7a 75 20 6d 65 72 69 6a 61 6a 20 66 65 6d 65 6a } //1 Wohovofawamuj jurajakotirih juteveyomulihac kefitixekoz mozerecona gezu merijaj femej
		$a_81_4 = {54 69 62 69 72 69 64 6f 76 61 64 65 68 20 6b 6f 64 6f 79 75 70 61 20 73 75 6d 61 62 69 73 65 6d 75 6e 61 7a 61 20 6b 6f 79 69 74 61 70 69 72 65 } //1 Tibiridovadeh kodoyupa sumabisemunaza koyitapire
		$a_81_5 = {52 65 78 69 74 69 67 61 79 6f 6c 20 7a 61 6a 61 68 61 64 65 6e 61 63 61 77 6f 73 20 66 75 6e 65 6c 75 7a 65 79 75 63 69 78 } //1 Rexitigayol zajahadenacawos funeluzeyucix
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=3
 
}