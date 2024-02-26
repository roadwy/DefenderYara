
rule Trojan_Win32_Strab_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Strab.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 fb 8a 81 90 01 04 c0 c8 03 32 82 90 01 04 88 81 90 01 04 8d 42 01 99 83 c1 03 f7 fb 8b f2 81 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}