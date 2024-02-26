
rule Trojan_Win32_NSISInjector_RZ_MTB{
	meta:
		description = "Trojan:Win32/NSISInjector.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c0 c8 03 32 82 a8 05 42 00 88 81 90 01 04 8d 42 01 99 f7 fe 0f b6 81 90 01 04 c0 c8 03 32 82 a8 05 42 00 88 81 90 01 04 8d 42 01 99 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}