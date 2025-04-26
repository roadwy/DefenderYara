
rule Trojan_Win32_ThemidaPacked_RT_MTB{
	meta:
		description = "Trojan:Win32/ThemidaPacked.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2e 74 68 65 6d 69 64 61 } //1 .themida
		$a_81_1 = {4d 42 4f 56 4b 54 6b 76 3a 34 61 } //1 MBOVKTkv:4a
		$a_81_2 = {4b 5f 4f 55 54 20 72 3d 30 25 64 63 57 4c 53 } //1 K_OUT r=0%dcWLS
		$a_81_3 = {6f 66 74 77 61 72 65 7e } //1 oftware~
		$a_81_4 = {2a 2f 63 68 65 30 6b 70 72 6f 6e 74 } //1 */che0kpront
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}