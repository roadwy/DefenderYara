
rule Trojan_Win32_Redline_GWG_MTB{
	meta:
		description = "Trojan:Win32/Redline.GWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 f8 0f b6 84 3d 90 01 04 88 84 1d 90 01 04 8b c3 8b 5d f4 88 8c 3d 90 01 04 0f b6 84 05 90 01 04 03 c2 0f b6 c0 0f b6 84 05 f0 fe ff ff 30 46 ff 8b 45 f8 85 db 75 a5 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}