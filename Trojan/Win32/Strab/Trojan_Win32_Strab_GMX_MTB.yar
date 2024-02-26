
rule Trojan_Win32_Strab_GMX_MTB{
	meta:
		description = "Trojan:Win32/Strab.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 c9 8a 81 90 01 04 c0 c8 03 32 83 90 01 04 88 81 90 01 04 8d 43 01 6a 0d 99 5e f7 fe 41 b8 90 01 04 8b da 3b c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}