
rule Trojan_Win32_DarkGate_B_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 14 24 8a 54 32 ff 8a 4c 1d ff 32 d1 88 54 30 ff 8b c5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}