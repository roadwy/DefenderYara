
rule Trojan_Win64_Dacic_SXA_MTB{
	meta:
		description = "Trojan:Win64/Dacic.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 74 65 61 6c 20 74 6f 6b 65 6e } //10 steal token
		$a_01_1 = {4b 65 79 6c 6f 67 67 65 72 20 73 74 61 72 74 65 64 } //10 Keylogger started
		$a_01_2 = {42 72 6f 77 73 65 72 50 69 76 6f 74 20 69 6e 6a 65 63 74 69 6f 6e } //5 BrowserPivot injection
		$a_01_3 = {54 61 6b 69 6e 67 20 73 63 72 65 65 6e 73 68 6f 74 } //5 Taking screenshot
		$a_01_4 = {43 72 65 64 65 6e 74 69 61 6c 20 6d 6f 64 75 6c 65 } //2 Credential module
		$a_01_5 = {53 74 65 61 6c 74 68 20 66 65 61 74 75 72 65 73 } //2 Stealth features
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=34
 
}