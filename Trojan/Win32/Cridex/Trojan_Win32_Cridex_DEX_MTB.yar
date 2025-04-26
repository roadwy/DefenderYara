
rule Trojan_Win32_Cridex_DEX_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_81_0 = {65 72 6b 74 62 38 39 75 6b 33 35 62 38 75 33 35 39 6b 38 79 6a 34 35 38 68 6a 38 33 75 } //1 erktb89uk35b8u359k8yj458hj83u
		$a_81_1 = {46 57 49 49 46 59 53 67 6e 47 } //1 FWIIFYSgnG
		$a_81_2 = {46 73 74 59 73 4a 57 51 65 44 } //1 FstYsJWQeD
		$a_81_3 = {59 42 41 79 76 57 73 4b 49 4c } //1 YBAyvWsKIL
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=2
 
}