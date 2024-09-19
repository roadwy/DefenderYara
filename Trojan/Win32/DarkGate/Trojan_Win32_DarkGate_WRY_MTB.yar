
rule Trojan_Win32_DarkGate_WRY_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.WRY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 48 64 8b 86 88 00 00 00 88 1c 01 a1 ?? ?? ?? ?? ff 40 64 ?? ?? ?? ?? 00 8b 8e d8 00 00 00 2b 88 ac 00 00 00 8b 86 e0 00 00 00 83 f1 f7 2b 86 ?? ?? ?? ?? 01 8e 18 01 00 00 05 6b 62 20 00 0f af 86 84 00 00 00 89 86 84 00 00 00 a1 ?? ?? ?? ?? 48 31 46 14 81 fd e8 d3 01 00 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}