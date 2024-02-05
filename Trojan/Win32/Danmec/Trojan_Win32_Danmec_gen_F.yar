
rule Trojan_Win32_Danmec_gen_F{
	meta:
		description = "Trojan:Win32/Danmec.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb 1e 34 1f 88 04 1f 43 46 8a 06 84 c0 74 15 0f be c0 40 85 c0 74 07 46 48 80 3e 00 75 f5 8a 06 84 c0 75 de 57 51 c6 04 1f 00 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 66 74 } //00 00 
	condition:
		any of ($a_*)
 
}