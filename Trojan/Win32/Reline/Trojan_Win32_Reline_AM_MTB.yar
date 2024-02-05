
rule Trojan_Win32_Reline_AM_MTB{
	meta:
		description = "Trojan:Win32/Reline.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 39 8e e3 38 8d b5 90 01 04 f7 e7 8b c7 03 f7 c1 ea 02 8d 0c 90 01 01 03 c9 2b c1 90 02 18 30 06 b8 39 8e e3 38 f7 e1 8b c7 83 c7 02 c1 ea 02 8d 0c 90 01 01 03 c9 2b c1 0f b6 80 90 01 04 30 46 01 81 ff 7e 07 00 00 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}