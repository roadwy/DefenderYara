
rule Trojan_Win32_LiteDuke_A_dha{
	meta:
		description = "Trojan:Win32/LiteDuke.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 f6 56 57 56 56 56 b8 00 00 00 80 50 56 50 68 00 00 cf 00 56 b9 } //10
		$a_02_1 = {68 be dd 54 7e 90 02 06 e8 90 00 } //10
		$a_02_2 = {68 1a 0e 38 59 90 02 06 e8 90 00 } //10
		$a_01_3 = {40 00 32 11 32 d0 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_01_3  & 1)*10) >=10
 
}