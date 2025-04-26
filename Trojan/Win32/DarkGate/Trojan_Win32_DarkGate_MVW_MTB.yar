
rule Trojan_Win32_DarkGate_MVW_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MVW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 06 8b 4e 34 2d 4f 38 12 00 0f af 46 54 89 46 54 a1 ?? ?? ?? ?? 88 1c 08 ff 46 34 8b 0d ?? ?? ?? ?? 8b 41 54 2d bc a0 11 00 31 81 80 00 00 00 81 ff e8 14 00 00 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}