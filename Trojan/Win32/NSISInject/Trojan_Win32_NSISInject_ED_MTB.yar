
rule Trojan_Win32_NSISInject_ED_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 50 6a 00 ff 15 } //01 00 
		$a_03_1 = {88 01 41 4e 75 90 01 01 6a 00 6a 00 57 ff 15 90 01 04 81 fb d9 58 00 00 74 0d c2 55 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}