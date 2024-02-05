
rule Trojan_Win32_Redline_MAC_MTB{
	meta:
		description = "Trojan:Win32/Redline.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 4d 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 0c 33 90 01 01 fc 33 d2 33 45 90 01 01 89 15 90 00 } //01 00 
		$a_03_1 = {8b c3 c1 e8 90 01 01 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}