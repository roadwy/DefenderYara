
rule Trojan_BAT_LummaC_DA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_02_0 = {2f 00 2f 00 31 00 39 00 33 00 2e 00 32 00 33 00 33 00 2e 00 32 00 35 00 34 00 2e 00 30 00 2f 00 [0-32] 2e 00 65 00 78 00 65 00 } //10
		$a_02_1 = {2f 2f 31 39 33 2e 32 33 33 2e 32 35 34 2e 30 2f [0-32] 2e 65 78 65 } //10
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  1
		$a_80_3 = {72 75 6e 61 73 } //runas  1
		$a_80_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 } //C:\Windows\Temp  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=13
 
}