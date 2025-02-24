
rule Trojan_Win32_Guloader_GTM_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {5c 6d 61 66 69 61 5c 73 68 74 2e 52 75 64 } //\mafia\sht.Rud  1
		$a_80_1 = {67 65 68 65 6a 6d 65 72 61 61 64 65 72 6e 65 73 20 6b 65 6e 64 65 74 65 67 6e 65 73 20 66 6f 6f 79 6f 75 6e 67 } //gehejmeraadernes kendetegnes fooyoung  1
		$a_80_2 = {74 65 6d 70 65 73 74 75 6f 75 73 6c 79 } //tempestuously  1
		$a_80_3 = {62 65 64 73 69 63 6b 20 64 69 63 68 72 6f 6d 61 74 6f 70 73 69 61 } //bedsick dichromatopsia  1
		$a_80_4 = {4e 72 68 65 64 73 62 75 74 69 6b 6b 65 6e 73 } //Nrhedsbutikkens  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}