
rule Trojan_Win32_DarkGate_EABR_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.EABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 86 b8 00 00 00 0f af da 8b d3 c1 ea 08 88 14 01 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}