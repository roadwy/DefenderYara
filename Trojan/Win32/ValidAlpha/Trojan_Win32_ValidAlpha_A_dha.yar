
rule Trojan_Win32_ValidAlpha_A_dha{
	meta:
		description = "Trojan:Win32/ValidAlpha.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {c7 00 ab cd c6 40 02 ef 90 01 01 03 00 00 00 48 89 c1 90 01 01 03 00 00 00 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}