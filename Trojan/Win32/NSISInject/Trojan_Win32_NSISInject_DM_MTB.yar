
rule Trojan_Win32_NSISInject_DM_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 f9 c4 12 00 00 74 90 01 01 04 d2 34 b8 fe c0 fe c0 34 6a fe c8 04 99 34 7e 2c f2 2c d8 fe c8 fe c8 88 84 0d 90 01 04 83 c1 01 eb 90 09 07 00 8a 84 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}