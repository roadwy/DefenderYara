
rule Trojan_BAT_RedLine_MR_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 fd a2 35 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 39 00 00 00 27 00 00 00 4a 00 00 00 65 } //10
		$a_01_1 = {63 6f 6f 6b 69 65 } //1 cookie
		$a_01_2 = {43 72 74 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 } //1 CrtImplementationDetails
		$a_01_3 = {44 6f 6d 61 69 6e 55 6e 6c 6f 61 64 } //1 DomainUnload
		$a_01_4 = {53 6b 69 70 56 65 72 69 66 69 63 61 74 69 6f 6e } //1 SkipVerification
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}