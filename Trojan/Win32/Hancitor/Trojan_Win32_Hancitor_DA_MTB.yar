
rule Trojan_Win32_Hancitor_DA_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 e4 03 45 e8 8b 55 ec 31 02 83 45 e8 04 e8 90 01 04 8b d8 83 c3 04 e8 90 01 04 2b d8 01 5d ec 8b 45 e8 3b 45 e0 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}