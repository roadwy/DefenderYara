
rule Trojan_Win32_Tibs_gen_L{
	meta:
		description = "Trojan:Win32/Tibs.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e3 06 c1 e3 0a 01 df 83 ef 04 81 ef 00 80 00 00 81 ef 00 80 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}