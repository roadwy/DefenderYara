
rule Trojan_Win32_Guloader_LWS_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 66 66 72 64 69 67 65 6c 73 65 72 73 2e 74 6f 70 } //1 affrdigelsers.top
		$a_81_1 = {71 75 69 6e 6f 76 69 63 2e 70 61 61 } //1 quinovic.paa
		$a_81_2 = {73 61 6c 74 6c 61 67 65 73 2e 64 61 67 } //1 saltlages.dag
		$a_81_3 = {56 61 6c 69 64 61 74 69 6e 67 32 33 30 2e 74 69 6c } //1 Validating230.til
		$a_81_4 = {61 6b 74 69 76 65 72 69 6e 67 65 72 6e 65 73 } //1 aktiveringernes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}