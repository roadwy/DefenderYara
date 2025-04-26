
rule Trojan_Win32_Netwire_PB_MTB{
	meta:
		description = "Trojan:Win32/Netwire.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 54 38 03 8a 0c 38 8a 5c 38 01 8a 6c 38 02 88 55 ?? c0 65 ?? ?? 8a 45 ff 24 ?? 0a c8 8a c2 c0 e0 06 80 e2 ?? 88 45 ?? 0a e8 8b 45 ?? c0 e2 ?? 0a d3 88 0c 06 88 54 06 01 83 c6 02 88 2c 06 81 fe ?? ?? 00 00 77 ?? [0-10] 8b 45 ?? 03 7d ?? 46 3b 3d ?? ?? ?? ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}