
rule Trojan_Win32_Zusy_GPAC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {8a 84 1c 30 01 00 00 30 86 90 01 04 46 8b 5c 24 1c 8b 54 24 10 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}