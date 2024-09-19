
rule Trojan_Win32_DarkGate_JZE_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.JZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 02 a1 ?? ?? ?? ?? 33 48 38 8b 80 88 00 00 00 89 0c 02 83 c2 04 a1 ?? ?? ?? ?? 8b 8f a4 00 00 00 2b 48 50 41 0f af 4f 1c 89 4f 1c a1 ?? ?? ?? ?? 01 47 38 81 fa dc 96 17 00 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}