
rule Trojan_Win32_BrakeCheck_A_dha{
	meta:
		description = "Trojan:Win32/BrakeCheck.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 03 00 00 64 00 "
		
	strings :
		$a_43_0 = {e0 01 83 e8 01 f7 d0 89 90 01 02 8b 90 01 02 d1 e9 8b 90 01 02 23 90 01 02 33 ca 89 90 01 02 eb 90 00 64 } //00 10 
		$a_68_1 = {85 99 ad 68 19 81 38 86 68 5f d7 f1 88 e8 64 00 10 41 68 d1 71 05 ad 68 36 6a 1f e1 68 59 81 7e ad e8 00 00 5d 04 00 00 c8 2b 05 80 5c 30 00 00 c9 2b 05 80 00 00 01 00 08 00 1a 00 54 72 6f 6a 61 } //6e 3a 
	condition:
		any of ($a_*)
 
}