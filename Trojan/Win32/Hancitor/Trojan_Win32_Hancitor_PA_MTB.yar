
rule Trojan_Win32_Hancitor_PA_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 11 89 15 90 01 04 a1 90 01 04 2d 59 11 00 00 a3 90 01 04 90 02 40 8b 15 90 01 04 81 c2 59 11 00 00 a1 90 01 04 8b ca 90 08 a0 01 31 0d 90 01 04 90 02 f0 a1 90 01 04 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 5f 5d c3 90 00 } //14 00 
		$a_02_1 = {55 8b ec 51 8b 45 0c 89 45 fc 8b 0d 90 01 04 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 8a 10 00 00 8b 45 08 89 10 8b 4d 08 8b 11 81 ea 8a 10 00 00 8b 45 08 89 10 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}