
rule Trojan_Win32_Fragtor_KAG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {99 f7 ff 0f b6 81 90 01 04 c0 c8 03 32 82 90 01 04 88 81 90 01 04 8d 42 01 99 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}