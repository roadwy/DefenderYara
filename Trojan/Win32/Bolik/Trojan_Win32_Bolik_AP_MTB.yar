
rule Trojan_Win32_Bolik_AP_MTB{
	meta:
		description = "Trojan:Win32/Bolik.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {8b 31 c1 ce 90 01 01 29 fe c1 ce 90 01 01 c1 c6 90 01 01 81 c6 90 02 04 01 de 31 fe 31 fe 81 ef 04 00 00 00 89 31 81 c1 04 00 00 00 81 ff 00 00 00 00 77 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}