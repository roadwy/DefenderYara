
rule Trojan_Win32_Zusy_GPAF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {03 c6 83 fe 07 0f 45 c8 0f b6 01 b9 01 00 00 00 30 84 3d 90 01 04 83 fe 07 8d 46 02 0f 45 c8 33 d2 83 f9 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}