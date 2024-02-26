
rule Trojan_Win32_Strab_GMP_MTB{
	meta:
		description = "Trojan:Win32/Strab.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {c0 c8 03 32 86 90 01 04 88 81 90 01 04 8d 46 01 99 41 f7 fb 8b f2 81 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}