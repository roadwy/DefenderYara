
rule Trojan_Win32_GootKit_SF{
	meta:
		description = "Trojan:Win32/GootKit.SF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {31 c0 0b 05 90 01 04 c7 05 90 01 04 00 00 00 00 8b 00 01 05 90 01 04 8d 35 90 01 04 81 2e 90 01 04 0f 82 90 01 04 ff 36 5e 83 7d fc 00 75 02 74 11 8d 05 90 01 04 01 05 90 01 04 e8 90 01 04 8d 0d 90 01 04 ff 35 90 01 04 58 01 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}