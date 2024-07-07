
rule Trojan_Win32_RedLine_RPY_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 8b c8 c1 ea 05 03 54 24 34 c1 e1 04 03 4c 24 24 03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLine_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2c ce 50 b8 ff 56 00 00 b8 52 2e 00 00 58 51 59 90 88 04 0b 52 52 5a ba 4f 75 00 00 52 eb 05 6e 92 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLine_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 c1 cf 51 c1 ea ba 66 81 c3 8d 01 c1 d6 7a 42 66 0b c7 c1 d0 22 66 0d e8 01 66 4e 66 f7 ea c1 d1 fd 66 c1 db 79 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLine_RPY_MTB_4{
	meta:
		description = "Trojan:Win32/RedLine.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 7c 24 10 c7 44 24 1c 00 00 00 00 8b 44 24 28 01 44 24 1c 8b 44 24 14 90 01 44 24 1c 8b 44 24 1c 89 44 24 20 8b 4c 24 18 8b 54 24 14 d3 ea 8b cb 8d 44 24 24 89 54 24 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}