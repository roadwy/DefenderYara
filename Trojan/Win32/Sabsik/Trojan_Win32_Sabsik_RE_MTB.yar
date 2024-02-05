
rule Trojan_Win32_Sabsik_RE_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ed 6b b1 55 b0 61 84 f5 36 14 18 29 7a d1 11 0d 98 88 6a ab bd c9 62 5c a0 eb e4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sabsik_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Sabsik.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 16 8b c2 8b cb d3 e8 8b 4d 08 d3 e2 4f 8d 76 04 0b 55 fc 89 00 fc 89 56 fc 85 00 } //00 00 
	condition:
		any of ($a_*)
 
}