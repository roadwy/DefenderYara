
rule Trojan_Win32_NSISInject_EL_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 50 53 ff 15 } //01 00 
		$a_03_1 = {8b 0c 24 80 90 01 03 40 39 c6 75 90 01 01 8b 04 24 ff e0 83 c4 0c 5e 5f 5b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}