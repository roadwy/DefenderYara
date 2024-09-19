
rule Trojan_Win32_DarkGate_MVV_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 14 07 83 c7 04 8b 86 e8 00 00 00 35 36 67 03 00 29 41 08 8b 9e 80 00 00 00 a1 ?? ?? ?? ?? 0f af da 8b 88 ac 00 00 00 8b 86 ?? ?? ?? ?? 8b d3 c1 ea 10 88 14 01 8b d3 ff 86 ?? ?? ?? ?? 8b 86 c8 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}