
rule Trojan_Win32_DarkGate_MKD_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b c8 0c 83 44 24 14 04 83 44 24 18 08 8b 04 83 0f af 83 e0 0a 00 00 31 81 e8 19 00 00 0f b6 05 ?? ?? ?? ?? 0f b6 4c 37 05 05 98 15 00 00 f7 f1 8b 4c 24 24 88 54 37 05 46 a1 ?? ?? ?? ?? 89 74 24 10 0f b6 04 08 3b f0 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}