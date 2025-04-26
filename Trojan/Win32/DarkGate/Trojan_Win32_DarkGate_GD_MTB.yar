
rule Trojan_Win32_DarkGate_GD_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 0f 41 89 c8 81 f9 07 7c 17 00 90 13 [0-1e] 31 d2 [0-1e] f7 f3 [0-1e] 8a 04 16 [0-0f] 83 c0 88 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}