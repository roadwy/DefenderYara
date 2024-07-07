
rule Trojan_Win32_Qakbot_PL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 70 64 74 } //1 Updt
		$a_01_1 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 GetKeyboardState
		$a_01_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}