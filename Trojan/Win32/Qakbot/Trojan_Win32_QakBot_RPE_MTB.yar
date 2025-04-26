
rule Trojan_Win32_QakBot_RPE_MTB{
	meta:
		description = "Trojan:Win32/QakBot.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d8 4b 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_QakBot_RPE_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.RPE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 50 46 30 0c 54 64 72 68 79 6d 77 34 6f 69 35 6a 0b 64 72 68 79 6d 77 34 6f 69 35 6a 04 4c 65 66 74 03 50 01 03 54 6f 70 03 87 00 05 57 69 64 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}