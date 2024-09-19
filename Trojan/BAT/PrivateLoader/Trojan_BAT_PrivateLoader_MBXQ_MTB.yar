
rule Trojan_BAT_PrivateLoader_MBXQ_MTB{
	meta:
		description = "Trojan:BAT/PrivateLoader.MBXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 50 6b 50 31 68 59 74 6a 6c 2e 46 73 35 52 44 77 34 44 79 67 4c } //1 bPkP1hYtjl.Fs5RDw4DygL
		$a_01_1 = {49 4d 4b 4a 58 45 00 41 4d 50 4b 43 51 4e 4e 45 41 58 56 42 50 } //1
		$a_01_2 = {52 4a 57 78 4c 67 58 43 6e } //1 RJWxLgXCn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}