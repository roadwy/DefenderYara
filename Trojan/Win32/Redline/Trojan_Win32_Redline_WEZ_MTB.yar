
rule Trojan_Win32_Redline_WEZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.WEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 f2 4b 88 55 a7 0f b6 45 a7 03 45 a8 88 45 a7 0f b6 4d a7 f7 d1 88 4d a7 0f b6 55 a7 83 ea 2b 88 55 a7 0f b6 45 a7 33 45 a8 88 45 a7 8b 4d a8 8a 55 a7 88 54 0d b8 e9 } //00 00 
	condition:
		any of ($a_*)
 
}