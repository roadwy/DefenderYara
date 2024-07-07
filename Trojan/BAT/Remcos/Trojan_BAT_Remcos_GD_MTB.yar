
rule Trojan_BAT_Remcos_GD_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {46 6f 72 74 6e 69 74 65 52 75 62 69 63 6f 6e 43 72 61 63 6b 65 64 } //1 FortniteRubiconCracked
		$a_81_1 = {75 70 6c 6f 6f 64 65 72 2e 6e 65 74 } //1 uplooder.net
		$a_81_2 = {77 65 6e 65 72 2f 20 67 69 66 6e 6f 63 70 69 } //1 wener/ gifnocpi
		$a_81_3 = {65 73 61 65 6c 65 72 2f 20 67 69 66 6e 6f 63 70 69 } //1 esaeler/ gifnocpi
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_5 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_81_6 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_7 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}