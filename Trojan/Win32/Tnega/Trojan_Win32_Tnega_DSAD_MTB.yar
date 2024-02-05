
rule Trojan_Win32_Tnega_DSAD_MTB{
	meta:
		description = "Trojan:Win32/Tnega.DSAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 fb 1a ca d3 d9 66 81 d3 73 12 8b 1c 24 0f c0 ed 0f bf c8 33 5c 24 04 } //01 00 
		$a_01_1 = {8b f8 0f a3 c1 33 fb 8b 1c 24 49 33 5c 24 04 49 0f c0 c9 8b cf } //00 00 
	condition:
		any of ($a_*)
 
}