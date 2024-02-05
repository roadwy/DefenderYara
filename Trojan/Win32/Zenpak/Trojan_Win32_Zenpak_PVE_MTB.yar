
rule Trojan_Win32_Zenpak_PVE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 45 c8 8b 4d fc 89 78 04 5f 89 30 5e 33 cd 5b e8 90 01 04 8b e5 5d c2 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}