
rule Trojan_Win32_BlackMoon_AB_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 0f b6 40 02 85 c0 75 27 64 a1 30 00 00 00 8b 40 68 83 e0 70 85 c0 75 17 64 a1 30 00 00 00 8b 40 18 83 78 0c 02 75 08 83 78 10 00 } //00 00 
	condition:
		any of ($a_*)
 
}