
rule Trojan_Win32_Redline_IMF_MTB{
	meta:
		description = "Trojan:Win32/Redline.IMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e2 06 0b ca 88 4d 90 01 01 0f b6 45 90 01 01 83 c0 48 88 45 90 01 01 0f b6 4d 90 01 01 c1 f9 02 0f b6 55 90 01 01 c1 e2 06 0b ca 88 4d 90 01 01 0f b6 45 90 01 01 2d 90 01 01 00 00 00 88 45 90 01 01 0f b6 4d 90 01 01 f7 d9 88 4d 90 01 01 8b 55 e0 8a 45 90 01 01 88 44 15 e4 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}