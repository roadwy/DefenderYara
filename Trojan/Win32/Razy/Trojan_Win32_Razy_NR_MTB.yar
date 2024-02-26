
rule Trojan_Win32_Razy_NR_MTB{
	meta:
		description = "Trojan:Win32/Razy.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {30 00 00 00 83 ec 90 01 01 75 05 74 03 33 bd 90 01 04 83 c4 04 eb 06 4c 29 c0 eb 05 2a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Razy_NR_MTB_2{
	meta:
		description = "Trojan:Win32/Razy.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 3f 81 eb 90 01 04 01 c9 81 e7 90 01 04 89 d9 29 cb 81 c2 90 01 04 89 cb 89 d9 81 fa 90 01 04 75 05 ba 00 00 00 00 01 cb 90 00 } //05 00 
		$a_03_1 = {31 3e f7 d3 89 d9 21 c9 81 c6 90 01 04 81 c1 01 00 00 00 21 c9 49 39 c6 0f 8c 96 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}