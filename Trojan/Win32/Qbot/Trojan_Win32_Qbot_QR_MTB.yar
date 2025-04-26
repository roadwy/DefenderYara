
rule Trojan_Win32_Qbot_QR_MTB{
	meta:
		description = "Trojan:Win32/Qbot.QR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {41 65 62 4f 71 4f 66 61 79 41 } //AebOqOfayA  1
		$a_80_1 = {42 47 47 45 79 75 4b } //BGGEyuK  1
		$a_80_2 = {42 6c 75 64 4b 52 52 } //BludKRR  1
		$a_80_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  1
		$a_80_4 = {46 62 6f 51 58 } //FboQX  1
		$a_80_5 = {48 77 7a 55 64 62 79 6a 69 6e } //HwzUdbyjin  1
		$a_80_6 = {53 44 7a 67 78 6e 68 4b 6f 44 } //SDzgxnhKoD  1
		$a_80_7 = {66 4f 7a 5a 55 78 65 } //fOzZUxe  1
		$a_80_8 = {66 77 55 55 77 71 74 71 55 69 } //fwUUwqtqUi  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}