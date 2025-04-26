
rule Trojan_Win32_ZorRoar_B_dha{
	meta:
		description = "Trojan:Win32/ZorRoar.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_41_0 = {8b ec 83 79 08 00 74 06 33 c0 5d c2 04 00 8b 45 08 89 41 04 c7 41 08 01 00 00 00 b8 01 00 00 00 5d c2 04 00 00 } //100
	condition:
		((#a_41_0  & 1)*100) >=100
 
}