
rule Trojan_Win32_Winnti_B_dha{
	meta:
		description = "Trojan:Win32/Winnti.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 2c 01 01 00 00 2c 01 "
		
	strings :
		$a_03_0 = {8a c8 80 e1 0f c0 e1 04 c0 e8 04 02 c8 88 0c 90 01 02 3b 90 01 01 72 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}