
rule Trojan_Win32_EyeStye_gen_D{
	meta:
		description = "Trojan:Win32/EyeStye.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_0a_0 = {50 6a 08 ff 15 90 01 04 50 06 1c ff 03 b0 f6 5d c3 33 c0 03 20 83 7d 08 00 74 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}