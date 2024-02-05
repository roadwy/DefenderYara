
rule Trojan_Win32_Duqu2_E_dha{
	meta:
		description = "Trojan:Win32/Duqu2.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 8d 04 10 49 83 c0 01 41 8a 0c 01 32 08 49 83 ea 01 42 88 90 01 04 00 00 75 e4 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}