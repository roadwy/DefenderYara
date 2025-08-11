
rule Trojan_Win32_Neoreblamy_CK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {89 55 f4 6b 4d f4 } //1
		$a_01_1 = {2b c8 03 4d e0 } //1
		$a_01_2 = {2b f8 8b 45 } //1
		$a_01_3 = {ff ff 59 59 8b 4d } //1
		$a_01_4 = {2b c8 03 4d e4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}