
rule Trojan_Win32_IcedID_PVP_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c7 50 96 26 01 89 3d ?? ?? ?? ?? 89 bc 30 ?? ?? ff ff 83 c6 04 8b 15 ?? ?? ?? ?? 8a c2 2a 05 ?? ?? ?? ?? 04 04 81 fe a2 13 00 00 0f 82 90 09 05 00 a1 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}