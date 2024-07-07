
rule Backdoor_Win32_Matchaldru_E_dha{
	meta:
		description = "Backdoor:Win32/Matchaldru.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 61 72 63 68 35 25 64 3f } //1 search5%d?
		$a_01_1 = {3d 25 73 26 68 34 3d 25 73 } //1 =%s&h4=%s
		$a_01_2 = {b2 64 b1 25 } //1
		$a_01_3 = {33 d2 8a c3 c0 e8 04 04 41 0f be c8 51 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}