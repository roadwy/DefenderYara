
rule Trojan_Win32_Predator_J_MTB{
	meta:
		description = "Trojan:Win32/Predator.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f6 d1 32 8c 14 90 01 04 88 8c 14 90 01 04 42 3b d7 73 09 8a 8c 24 90 01 04 eb e2 90 00 } //01 00 
		$a_01_1 = {55 8b ec 8a 01 f6 d0 32 45 08 5d c2 04 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}