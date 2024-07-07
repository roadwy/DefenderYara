
rule Trojan_Win32_Emotet_SO_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SO!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 44 52 41 57 2e 64 6c 6c } //1 DDRAW.dll
		$a_01_1 = {44 65 73 74 72 6f 79 57 69 6e 64 6f 77 } //1 DestroyWindow
		$a_01_2 = {53 65 74 46 69 6c 65 53 65 63 75 72 69 74 79 } //1 SetFileSecurity
		$a_01_3 = {42 72 6f 6b 65 6e 20 70 72 6f 6d 69 73 65 } //1 Broken promise
		$a_01_4 = {52 65 73 75 6d 65 20 47 61 6d 65 } //1 Resume Game
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}