
rule Trojan_Win32_Zenpak_GXY_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c1 6a 08 99 5e f7 fe 8a 82 90 01 04 30 81 90 01 04 41 81 f9 0c ac 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}