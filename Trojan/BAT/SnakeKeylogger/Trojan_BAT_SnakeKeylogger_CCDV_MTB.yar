
rule Trojan_BAT_SnakeKeylogger_CCDV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.CCDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 54 68 79 76 77 44 4a 42 6b 73 44 79 41 4a 5a 55 4d 54 6b 43 78 41 } //1 LThyvwDJBksDyAJZUMTkCxA
		$a_01_1 = {6b 69 55 68 4f 51 55 51 43 73 43 66 79 51 51 6e 76 76 70 54 73 6e 54 } //1 kiUhOQUQCsCfyQQnvvpTsnT
		$a_01_2 = {66 73 42 5a 51 68 43 69 73 69 72 45 42 4f 4f 55 66 79 44 43 54 73 54 } //1 fsBZQhCisirEBOOUfyDCTsT
		$a_01_3 = {78 70 43 42 6b 79 69 55 76 42 45 44 4c 77 79 78 4c 51 4c 70 66 4c 69 } //1 xpCBkyiUvBEDLwyxLQLpfLi
		$a_01_4 = {4c 51 76 77 6b 4d 70 79 55 4a 4d 70 55 4c 41 54 41 78 43 5a 76 } //1 LQvwkMpyUJMpULATAxCZv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}