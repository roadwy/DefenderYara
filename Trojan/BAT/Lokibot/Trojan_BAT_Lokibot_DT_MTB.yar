
rule Trojan_BAT_Lokibot_DT_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {46 6f 72 6d 43 6f 6d 70 6f 6e 65 6e 74 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 FormComponents.Properties.Resources
		$a_81_1 = {46 6f 72 6d 43 6f 6d 70 6f 6e 65 6e 74 73 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 FormComponents.Form1.resources
		$a_81_2 = {50 68 6f 74 6f 52 65 73 69 7a 65 72 } //1 PhotoResizer
		$a_81_3 = {56 69 72 74 75 61 6c 20 4b 65 79 62 6f 61 72 64 } //1 Virtual Keyboard
		$a_81_4 = {56 69 72 74 75 61 6c 20 4e 75 6d 70 61 64 } //1 Virtual Numpad
		$a_81_5 = {76 69 72 74 75 61 6c 4b 65 79 } //1 virtualKey
		$a_81_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_7 = {42 69 74 6d 61 70 } //1 Bitmap
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}