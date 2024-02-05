
rule Trojan_Win32_Cridex_MO_MTB{
	meta:
		description = "Trojan:Win32/Cridex.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {99 8b 4d f0 2b c8 8b 45 90 01 01 1b c2 66 89 4d ec 8b 0d 90 01 04 81 c1 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 55 e8 a1 90 01 04 89 42 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}