
rule Trojan_Win32_QakbotPacker_MTB{
	meta:
		description = "Trojan:Win32/QakbotPacker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 1c 30 90 02 30 83 e2 00 90 02 30 d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d 90 01 01 75 90 00 } //01 00 
		$a_03_1 = {0f b6 1c 30 90 02 30 d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_QakbotPacker_MTB_2{
	meta:
		description = "Trojan:Win32/QakbotPacker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c2 89 45 90 01 01 0f b6 0d 90 01 04 33 4d 90 01 01 89 4d 90 01 01 0f b6 15 90 01 04 03 55 90 01 01 89 55 90 01 01 a1 90 01 04 03 45 90 01 01 8a 4d 90 01 01 88 08 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}