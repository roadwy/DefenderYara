
rule Trojan_BAT_Heracles_GDI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {71 6c 34 77 73 59 47 61 6d 49 6e 56 6e 69 } //1 ql4wsYGamInVni
		$a_01_1 = {64 6d 61 73 41 73 79 73 74 65 6d 51 72 74 6c 73 75 70 70 6f 72 74 73 6c 31 77 31 45 30 } //1 dmasAsystemQrtlsupportsl1w1E0
		$a_01_2 = {42 74 68 53 51 61 73 6b 73 57 76 33 5f 31 35 33 } //1 BthSQasksWv3_153
		$a_01_3 = {47 65 74 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 } //1 GetCurrentDirectory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}