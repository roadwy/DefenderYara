
rule Trojan_Win32_NSISInject_EI_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 45 f0 50 6a 00 ff 15 } //01 00 
		$a_03_1 = {8b 4d f8 03 4d fc 88 01 e9 90 02 04 8b 45 f8 ff e0 33 c0 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}