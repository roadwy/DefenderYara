
rule Trojan_Win32_Redline_GJA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 99 b9 90 01 04 f7 f9 8b 45 08 0f be 0c 10 6b c9 3b 81 e1 90 01 04 79 90 01 01 49 83 c9 e0 41 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}