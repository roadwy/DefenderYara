
rule Trojan_Win32_Redline_GUD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 d1 83 e1 03 0f b6 89 90 01 04 30 8a 90 01 04 83 c2 90 01 01 81 fa 00 66 01 00 75 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}