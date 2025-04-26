
rule Trojan_Win32_Zusy_MBHK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 74 76 79 62 75 46 74 76 79 62 } //1 HtvybuFtvyb
		$a_01_1 = {4b 6e 75 62 79 46 74 76 79 62 } //1 KnubyFtvyb
		$a_01_2 = {44 74 72 79 76 62 68 59 63 79 76 67 68 62 6a } //1 DtryvbhYcyvghbj
		$a_01_3 = {55 72 63 74 76 4b 74 63 76 79 62 } //1 UrctvKtcvyb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}