
rule Trojan_Win32_IcedID_DSK_MTB{
	meta:
		description = "Trojan:Win32/IcedID.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 05 cc cb e5 01 89 02 a3 90 01 04 66 89 35 90 01 04 a1 a4 4c 42 00 2b c7 83 c2 04 83 6c 24 14 01 0f b7 c8 89 54 24 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}