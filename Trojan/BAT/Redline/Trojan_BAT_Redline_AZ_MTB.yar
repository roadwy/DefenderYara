
rule Trojan_BAT_Redline_AZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {42 66 48 6e 62 4c 71 42 6c 77 72 54 64 67 45 70 70 69 73 } //1 BfHnbLqBlwrTdgEppis
		$a_81_1 = {6b 73 4a 59 53 49 78 6d 6f 6e 7a 46 69 77 61 62 43 68 79 4e 56 2e 64 6c 6c } //1 ksJYSIxmonzFiwabChyNV.dll
		$a_81_2 = {79 73 70 73 6b 74 48 68 54 68 51 79 51 55 6e 7a 69 76 79 69 53 4c 4a 50 6d 58 6d 4e } //1 yspsktHhThQyQUnzivyiSLJPmXmN
		$a_81_3 = {76 79 72 4a 66 63 6f 56 72 59 58 56 6d 66 7a 43 76 78 68 4f 4a 58 4c 65 55 4d 52 74 2e 64 6c 6c } //1 vyrJfcoVrYXVmfzCvxhOJXLeUMRt.dll
		$a_81_4 = {52 63 51 76 57 55 70 6f 41 54 54 6d 76 } //1 RcQvWUpoATTmv
		$a_81_5 = {7a 70 57 43 77 58 45 62 49 64 77 4c 58 58 4b 67 55 62 42 48 4e 50 2e 64 6c 6c } //1 zpWCwXEbIdwLXXKgUbBHNP.dll
		$a_81_6 = {4b 53 61 4f 52 42 43 73 78 66 67 64 6f 4b 5a 70 54 47 } //1 KSaORBCsxfgdoKZpTG
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}