
rule Trojan_Win32_Redline_UQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.UQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 45 fc 8b 4d fc 3b 4d 14 73 24 8b 45 fc 33 d2 f7 75 10 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f be 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb cb 8b 45 0c 8b e5 5d } //00 00 
	condition:
		any of ($a_*)
 
}