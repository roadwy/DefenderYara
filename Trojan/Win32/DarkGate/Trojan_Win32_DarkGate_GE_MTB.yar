
rule Trojan_Win32_DarkGate_GE_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 f9 07 e4 06 00 90 13 [0-32] 31 d2 [0-3c] f7 f3 [0-3c] 8a 04 16 [0-3c] 30 04 0f [0-3c] 41 [0-3c] 89 c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}