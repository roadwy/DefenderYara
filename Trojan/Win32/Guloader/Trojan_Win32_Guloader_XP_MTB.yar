
rule Trojan_Win32_Guloader_XP_MTB{
	meta:
		description = "Trojan:Win32/Guloader.XP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 76 65 72 65 6e 73 6b 6f 6d 73 74 61 6e 73 74 74 65 6c 73 65 73 } //1 Overenskomstansttelses
		$a_01_1 = {50 72 6f 6c 6f 67 6b 6c 61 75 73 75 6c 65 72 } //1 Prologklausuler
		$a_01_2 = {45 6c 65 6b 74 72 6f 69 6e 67 65 6e 69 72 65 72 6e 65 } //1 Elektroingenirerne
		$a_01_3 = {4b 75 72 73 75 73 70 6c 61 6e 65 6e 73 5c 4c 61 63 65 77 6f 72 6b 65 72 } //1 Kursusplanens\Laceworker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}