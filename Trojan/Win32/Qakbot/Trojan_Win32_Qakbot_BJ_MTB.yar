
rule Trojan_Win32_Qakbot_BJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //2 DllUnregisterServer
		$a_01_1 = {63 6f 6e 63 65 72 74 69 7a 65 72 } //2 concertizer
		$a_01_2 = {69 73 6f 70 61 72 61 66 66 69 6e } //2 isoparaffin
		$a_01_3 = {70 73 65 75 64 6f 62 72 61 63 68 69 61 6c } //2 pseudobrachial
		$a_01_4 = {74 61 70 70 65 72 65 72 } //2 tapperer
		$a_01_5 = {62 6f 64 79 77 6f 72 6b } //2 bodywork
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}