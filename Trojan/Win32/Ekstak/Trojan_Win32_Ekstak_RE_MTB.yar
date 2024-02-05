
rule Trojan_Win32_Ekstak_RE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 90 90 90 90 55 8b ec 8b 45 14 50 ff 15 e8 94 65 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 5e 5d c3 8b c6 5e 5d c3 90 01 05 55 8b ec 56 8b 75 14 56 ff 15 90 01 02 65 00 56 e8 90 01 02 20 00 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ekstak_RE_MTB_3{
	meta:
		description = "Trojan:Win32/Ekstak.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f1 a3 90 01 03 00 e8 90 01 02 fe ff 8b 15 90 01 03 00 a1 90 01 03 00 52 50 e8 90 09 19 00 6a 32 e8 90 01 03 00 01 05 90 01 03 00 e8 90 01 03 00 8b c8 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}