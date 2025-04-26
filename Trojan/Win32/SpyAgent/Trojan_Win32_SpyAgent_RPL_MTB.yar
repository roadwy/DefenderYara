
rule Trojan_Win32_SpyAgent_RPL_MTB{
	meta:
		description = "Trojan:Win32/SpyAgent.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 75 6e 67 61 69 6e 61 } //1 .ungaina
		$a_01_1 = {2e 72 65 66 75 74 61 62 } //1 .refutab
		$a_01_2 = {2e 69 6d 70 6c 75 6d 65 } //1 .implume
		$a_01_3 = {2e 74 75 72 62 6f 64 79 } //1 .turbody
		$a_01_4 = {2e 63 61 6c 76 69 6e 69 } //1 .calvini
		$a_01_5 = {2e 62 65 63 69 72 63 6c } //1 .becircl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}