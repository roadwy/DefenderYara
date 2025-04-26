
rule Trojan_Win32_Emotet_Q{
	meta:
		description = "Trojan:Win32/Emotet.Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 5c 6d 35 46 65 44 62 4d 39 33 54 2e 62 6e 00 } //1 尀㕭敆扄㥍吳戮n
		$a_01_1 = {00 67 6d 31 36 48 43 7a 00 } //1
		$a_01_2 = {00 69 4d 45 55 57 70 49 66 61 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}