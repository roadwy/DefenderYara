
rule Trojan_BAT_Redline_GA_MTB{
	meta:
		description = "Trojan:BAT/Redline.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {33 37 2e 31 33 39 2e 31 32 39 2e 31 34 32 } //37.139.129.142  1
		$a_80_1 = {50 54 31 47 62 46 42 4c 4d 47 52 31 55 6d 4e 32 62 47 56 6a 57 6c } //PT1GbFBLMGR1UmN2bGVjWl  1
		$a_01_2 = {48 00 52 00 30 00 63 00 44 00 6f 00 76 00 4c 00 7a 00 4d 00 33 00 4c 00 6a 00 45 00 7a 00 4f 00 } //1 HR0cDovLzM3LjEzO
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}