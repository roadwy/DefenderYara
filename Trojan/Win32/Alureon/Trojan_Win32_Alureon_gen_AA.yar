
rule Trojan_Win32_Alureon_gen_AA{
	meta:
		description = "Trojan:Win32/Alureon.gen!AA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 45 0b 01 89 45 90 01 01 e9 90 01 04 b8 43 46 00 00 66 39 85 90 01 04 0f 85 90 01 04 66 83 bd 90 01 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}