
rule Trojan_Win32_NativeZone_B_dha{
	meta:
		description = "Trojan:Win32/NativeZone.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {cc b8 01 00 00 00 c2 0c 00 cc cc cc cc cc cc cc cc b8 0c 00 00 00 c3 cc cc cc cc cc cc cc cc cc cc 55 8b ec 83 ec 34 a1 00 30 01 10 33 c5 89 45 fc 56 57 b9 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}