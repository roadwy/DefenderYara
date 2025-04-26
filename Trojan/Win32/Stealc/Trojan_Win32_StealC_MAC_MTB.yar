
rule Trojan_Win32_StealC_MAC_MTB{
	meta:
		description = "Trojan:Win32/StealC.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b de 8b 4d f4 03 c6 8b 55 fc d3 eb 33 d0 03 5d ?? 81 3d ?? ?? ?? ?? 03 0b 00 00 89 5d f0 89 55 fc 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}