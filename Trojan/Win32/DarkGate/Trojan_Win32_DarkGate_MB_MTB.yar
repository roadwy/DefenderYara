
rule Trojan_Win32_DarkGate_MB_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 44 10 ff 50 a1 90 01 04 8a 44 07 ff 8b 15 90 01 04 8a 54 16 ff 32 c2 5a 88 02 8b c6 e8 90 01 04 3b 05 90 01 04 7e 08 ff 05 90 01 04 eb 0a c7 05 90 01 04 01 00 00 00 ff 05 90 01 04 4b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}