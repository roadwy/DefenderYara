
rule Trojan_Win32_Qakbot_PP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 6c 41 75 74 6f 4f 70 65 6e } //1 xlAutoOpen
		$a_01_1 = {5a 4d 44 47 79 7a 31 30 34 77 71 7a } //1 ZMDGyz104wqz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}