
rule Trojan_BAT_AveMariaRat_MX_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRat.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {0b 07 16 07 90 0a 22 00 06 6f 22 00 00 0a 00 00 de 05 26 00 00 de 00 72 29 00 00 70 28 05 00 00 06 [0-06] 8e 69 28 23 00 00 0a 00 07 0c 2b 00 08 2a } //1
		$a_01_1 = {53 61 6e 74 61 } //1 Santa
		$a_01_2 = {47 65 74 54 65 61 63 68 65 72 } //1 GetTeacher
		$a_01_3 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_5 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}