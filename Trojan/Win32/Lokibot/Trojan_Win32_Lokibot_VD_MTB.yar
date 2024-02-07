
rule Trojan_Win32_Lokibot_VD_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc bf 90 02 40 8a 01 34 90 01 01 8b d3 03 55 90 01 01 90 13 88 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Lokibot_VD_MTB_2{
	meta:
		description = "Trojan:Win32/Lokibot.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 02 88 45 90 02 25 8b 84 9d 90 01 04 03 84 bd 90 02 40 8a 84 85 90 01 04 32 45 90 01 01 8b 4d 90 01 01 88 01 ff 45 90 01 01 42 ff 4d 90 00 } //01 00 
		$a_03_1 = {8b ce c1 e1 90 01 01 8b fe c1 ef 90 01 01 03 cf 0f be 3a 03 cf 33 f1 42 48 0f 85 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}