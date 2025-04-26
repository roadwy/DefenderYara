
rule Trojan_Win32_DarkGate_EAA_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.EAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8e b8 00 00 00 8b 86 84 00 00 00 c1 ea 08 88 14 01 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}