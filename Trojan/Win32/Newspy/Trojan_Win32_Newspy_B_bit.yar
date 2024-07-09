
rule Trojan_Win32_Newspy_B_bit{
	meta:
		description = "Trojan:Win32/Newspy.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 25 ?? ?? ?? ?? 33 d2 bb ?? ?? ?? ?? f7 f3 41 0a c3 2a c2 30 44 0f ff 8b 45 ?? 3b c8 72 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}