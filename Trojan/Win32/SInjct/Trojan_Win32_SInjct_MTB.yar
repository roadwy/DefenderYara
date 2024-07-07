
rule Trojan_Win32_SInjct_MTB{
	meta:
		description = "Trojan:Win32/SInjct!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 49 89 ca 0f 05 } //1
		$a_00_1 = {41 59 41 58 5a 59 49 89 ca 0f 05 } //1
		$a_02_2 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 90 02 05 48 8b 48 10 90 02 05 4c 8b 59 30 90 00 } //1
		$a_02_3 = {48 8b 8c 24 90 01 04 83 ca ff ff 15 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}