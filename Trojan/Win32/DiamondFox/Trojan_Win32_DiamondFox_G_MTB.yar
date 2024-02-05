
rule Trojan_Win32_DiamondFox_G_MTB{
	meta:
		description = "Trojan:Win32/DiamondFox.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c1 f7 f7 8a 99 90 01 04 41 0f be 82 90 01 04 03 f0 0f b6 d3 03 f2 81 e6 ff 00 00 00 8a 86 90 01 04 88 81 90 01 04 88 9e 90 01 04 81 f9 00 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}