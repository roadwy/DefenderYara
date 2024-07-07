
rule Trojan_Win32_Tibs_JH{
	meta:
		description = "Trojan:Win32/Tibs.JH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 be 46 00 f2 0f f0 90 02 02 66 0f d0 d8 6a 00 6a 00 66 0f d6 1c 24 90 00 } //1
		$a_01_1 = {c7 45 d4 20 55 26 02 c7 45 d8 10 44 65 22 c7 45 dc 56 69 72 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}