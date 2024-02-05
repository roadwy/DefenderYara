
rule Trojan_Win32_Nebuler_Q{
	meta:
		description = "Trojan:Win32/Nebuler.Q,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 42 01 8b 8d 90 01 04 0f be 91 90 01 04 33 c2 8b 8d 90 01 04 03 8d 90 01 04 88 01 90 09 09 00 8b 55 08 03 95 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}