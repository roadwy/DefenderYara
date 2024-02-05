
rule Trojan_Win32_IcedId_QA_MTB{
	meta:
		description = "Trojan:Win32/IcedId.QA!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 04 24 44 01 d0 83 c0 02 89 04 24 f7 04 24 03 00 00 00 0f 85 17 01 00 00 } //0a 00 
		$a_01_1 = {b8 6d e3 4c 00 89 04 24 89 44 24 04 f7 04 24 03 00 00 00 74 1e 41 83 f8 0a 0f 9c c2 41 8d 41 ff 41 0f af c1 83 e0 01 0f 94 c1 08 d1 80 f9 01 } //00 00 
	condition:
		any of ($a_*)
 
}