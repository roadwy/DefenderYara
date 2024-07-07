
rule Trojan_Win32_DarkGate_A_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 0f b6 44 18 90 01 01 33 f8 43 4e 90 00 } //2
		$a_03_1 = {8b d7 32 54 1d 90 01 01 f6 d2 88 54 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}