
rule Trojan_Win32_Uascape_A{
	meta:
		description = "Trojan:Win32/Uascape.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e } //1 ConsentPromptBehaviorAdmin
		$a_01_1 = {48 69 64 65 53 43 41 48 65 61 6c 74 68 } //1 HideSCAHealth
		$a_01_2 = {4c 6f 77 52 69 73 6b 46 69 6c 65 54 79 70 65 73 } //1 LowRiskFileTypes
		$a_01_3 = {24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 } //10 $$\wininit.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10) >=13
 
}