
rule Trojan_Win32_Redline_CAK_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 99 b9 90 02 04 f7 f9 8b 45 08 0f be 0c 10 69 c9 90 02 04 81 e1 ff 00 00 00 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}