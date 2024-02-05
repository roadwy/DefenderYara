
rule Trojan_Win32_NSISInject_EG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 45 f0 50 6a 00 ff 15 } //01 00 
		$a_03_1 = {6a 00 6a 00 8b 55 f8 52 ff 15 90 01 04 33 c0 8b e5 5d c3 90 09 07 00 88 01 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}